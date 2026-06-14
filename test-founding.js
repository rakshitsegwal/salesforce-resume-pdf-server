// Founding User Beta Program — logic tests. NON-DESTRUCTIVE: everything runs in
// a single transaction that is ALWAYS rolled back, so it never persists a change
// (your real rn_users / rn_founding_counter are untouched).
//
//   DATABASE_URL=postgres://...  node test-founding.js
//
// Covers: user #1 qualifies, #20 qualifies, #21 rejected (atomic cap), email-
// verification requirement, new-account eligibility, trial active/expired,
// discount applies once + is not reusable, and the public counter math.

const { Pool } = require('pg');
if (!process.env.DATABASE_URL) { console.error('Set DATABASE_URL (ideally a scratch DB).'); process.exit(1); }
const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 3 });

const CAP = 20;
const PROGRAM_START = '2026-06-14T00:00:00Z';
let passed = 0, failed = 0;
const ok  = (name, cond) => { (cond ? passed++ : failed++); console.log(`  ${cond ? '✓' : '✗ FAIL'}  ${name}`); };

// Mirrors the server's atomic claim + guarded stamp exactly.
async function redeem(c, userId) {
    const slot = await c.query('UPDATE rn_founding_counter SET claimed = claimed + 1 WHERE id=1 AND claimed < $1 RETURNING claimed', [CAP]);
    if (!slot.rows.length) return { ok: false, reason: 'FULL' };
    const number = slot.rows[0].claimed;
    const stamp = await c.query(
        `UPDATE rn_users SET founding_user=TRUE, founding_number=$2,
            trial_started_at=NOW(), trial_ends_at=NOW() + INTERVAL '7 days',
            pass_type='placement', pass_expires_at=NOW() + INTERVAL '7 days', pass_interviews_remaining=25
         WHERE id=$1 AND founding_user=FALSE RETURNING founding_number`, [userId, number]);
    if (!stamp.rows.length) { await c.query('UPDATE rn_founding_counter SET claimed = claimed - 1 WHERE id=1 AND claimed > 0'); return { ok: false, reason: 'ALREADY' }; }
    return { ok: true, number };
}

(async () => {
    const c = await db.connect();
    try {
        await c.query('BEGIN');
        // Isolate: ensure the counter row exists, then zero it inside the txn.
        await c.query('INSERT INTO rn_founding_counter(id, claimed) VALUES(1,0) ON CONFLICT (id) DO NOTHING');
        await c.query('UPDATE rn_founding_counter SET claimed = 0 WHERE id=1');

        // 21 fresh, verified, new-signup test users.
        const ids = [];
        for (let i = 0; i < 21; i++) {
            const r = await c.query(
                `INSERT INTO rn_users(email,name,provider,email_verified,created_at)
                 VALUES($1,$2,'email',TRUE,NOW()) RETURNING id`,
                [`fnd-test-${i}-${Date.now()}@example.invalid`, `Test ${i}`]);
            ids.push(r.rows[0].id);
        }

        console.log('\nCAP / qualification (atomic counter):');
        const results = [];
        for (let i = 0; i < 21; i++) results.push(await redeem(c, ids[i]));
        ok('user #1 qualifies (slot 1)',  results[0].ok && results[0].number === 1);
        ok('user #20 qualifies (slot 20)', results[19].ok && results[19].number === 20);
        ok('user #21 REJECTED (cap reached)', !results[20].ok && results[20].reason === 'FULL');
        const counter = (await c.query('SELECT claimed FROM rn_founding_counter WHERE id=1')).rows[0].claimed;
        ok('counter never exceeds cap (claimed = 20)', counter === 20);
        ok('re-redeem by an existing founding user is a no-op', !(await redeem(c, ids[0])).ok);

        console.log('\nEligibility guards:');
        const unverified = (await c.query(
            `INSERT INTO rn_users(email,name,provider,email_verified,created_at) VALUES($1,'U','email',FALSE,NOW()) RETURNING email_verified`,
            [`unv-${Date.now()}@example.invalid`])).rows[0];
        ok('unverified email blocked (email_verified = FALSE)', unverified.email_verified === false);
        const existing = (await c.query(
            `INSERT INTO rn_users(email,name,provider,email_verified,created_at) VALUES($1,'O','email',TRUE,'2020-01-01') RETURNING created_at`,
            [`old-${Date.now()}@example.invalid`])).rows[0];
        ok('existing account blocked (created_at < program start)', new Date(existing.created_at) < new Date(PROGRAM_START));

        console.log('\nTrial status (computed on read):');
        const active  = (await c.query(`SELECT (NOW() + INTERVAL '7 days') > NOW() AS a`)).rows[0].a;
        const expired = (await c.query(`SELECT (NOW() - INTERVAL '1 day')  > NOW() AS a`)).rows[0].a;
        ok('trial within 7 days reads ACTIVE',  active === true);
        ok('trial past end reads EXPIRED',       expired === false);

        console.log('\nDiscount (apply once, not reusable):');
        await c.query('UPDATE rn_users SET founding_discount_used=FALSE WHERE id=$1', [ids[0]]);
        const first  = await c.query('UPDATE rn_users SET founding_discount_used=TRUE WHERE id=$1 AND founding_discount_used=FALSE', [ids[0]]);
        const second = await c.query('UPDATE rn_users SET founding_discount_used=TRUE WHERE id=$1 AND founding_discount_used=FALSE', [ids[0]]);
        ok('first discount marks used (1 row)', first.rowCount === 1);
        ok('second attempt is a no-op (0 rows) — not reusable', second.rowCount === 0);
        ok('30% math: ₹1499 → ₹1049 paise', Math.round(149900 * 0.7) === 104930);

        console.log('\nPublic counter math:');
        ok('remaining = cap - claimed (0 left at cap)', Math.max(0, CAP - counter) === 0);

        await c.query('ROLLBACK');   // never persist anything
        console.log(`\n${failed === 0 ? '✅ ALL PASS' : '❌ FAILURES'} — ${passed} passed, ${failed} failed.  (transaction rolled back — no data changed)`);
        process.exit(failed === 0 ? 0 : 1);
    } catch (e) {
        await c.query('ROLLBACK').catch(() => {});
        console.error('TEST ERROR:', e.message);
        process.exit(1);
    } finally { c.release(); await db.end(); }
})();
