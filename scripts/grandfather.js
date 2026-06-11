// Grandfather migration — old plans → credit ladder (run once, manually).
//
//   DATABASE_URL=postgres://...  node scripts/grandfather.js            # DRY RUN (prints, writes nothing)
//   DATABASE_URL=postgres://...  node scripts/grandfather.js --apply    # performs the migration
//
// What it does (idempotent — safe to re-run):
//   1. Active Coach Unlimited users (coach_plan='unlimited', not expired):
//      +20 credits (ledger reason 'grandfather'), grandfathered=TRUE.
//      Their unlimited access is NOT revoked — it lapses at coach_expires.
//   2. Session-pass holders (session_passes > 0): converted 1:1 into
//      interview_credits (the new single-interview counter); passes zeroed.
//   3. Backfills referral_code for every user missing one.
//   4. Prints the full list of affected users for manual follow-up.
//
// NOTE: there are NO Razorpay mandates/subscriptions in this system — every
// historical payment was a one-time order — so there is nothing to cancel.

const { Pool } = require('pg');
const crypto = require('crypto');

const APPLY = process.argv.includes('--apply');
if (!process.env.DATABASE_URL) { console.error('Set DATABASE_URL.'); process.exit(1); }

const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 3 });

const makeReferralCode = () =>
    crypto.randomBytes(5).toString('base64url').replace(/[^a-zA-Z0-9]/g, 'x').slice(0, 8).toUpperCase();

(async () => {
    console.log(`Grandfather migration — ${APPLY ? 'APPLY' : 'DRY RUN (pass --apply to write)'}\n`);

    // 1. Active unlimited users → +20 credits + flag
    const unlimited = await db.query(
        `SELECT id, email, name, coach_expires FROM rn_users
         WHERE coach_plan='unlimited'
           AND (coach_expires IS NULL OR coach_expires > NOW())
           AND grandfathered = FALSE`);
    console.log(`Active Coach Unlimited users to grandfather: ${unlimited.rows.length}`);
    for (const u of unlimited.rows) {
        console.log(`  • ${u.email} (${u.id}) — unlimited until ${u.coach_expires || 'no expiry'} → +20 credits, grandfathered`);
        if (APPLY) {
            await db.query(
                `WITH ins AS (
                    INSERT INTO rn_credit_ledger(user_id, delta, reason, ref_id)
                    VALUES($1, 20, 'grandfather', 'migration-v14')
                )
                UPDATE rn_users SET credit_balance = credit_balance + 20, grandfathered = TRUE, updated_at = NOW()
                WHERE id = $1`, [u.id]);
        }
    }

    // 2. Session passes → interview credits (1:1)
    const passes = await db.query(
        `SELECT id, email, session_passes FROM rn_users WHERE session_passes > 0`);
    console.log(`\nSession-pass holders to convert: ${passes.rows.length}`);
    for (const u of passes.rows) {
        console.log(`  • ${u.email} (${u.id}) — ${u.session_passes} pass(es) → ${u.session_passes} interview credit(s)`);
        if (APPLY) {
            await db.query(
                `UPDATE rn_users SET interview_credits = interview_credits + session_passes,
                        session_passes = 0, updated_at = NOW()
                 WHERE id = $1`, [u.id]);
        }
    }

    // 3. Referral-code backfill
    const noCode = await db.query(`SELECT id, email FROM rn_users WHERE referral_code IS NULL`);
    console.log(`\nUsers missing a referral code: ${noCode.rows.length}`);
    for (const u of noCode.rows) {
        if (APPLY) {
            // retry on the (unlikely) unique collision
            for (let i = 0; i < 5; i++) {
                try { await db.query('UPDATE rn_users SET referral_code=$2 WHERE id=$1', [u.id, makeReferralCode()]); break; }
                catch (e) { if (i === 4) throw e; }
            }
        }
    }
    if (APPLY) console.log('Referral codes backfilled.');

    console.log(`\nDone. ${APPLY ? 'Changes written.' : 'Nothing written (dry run).'}`);
    await db.end();
})().catch(e => { console.error('MIGRATION FAILED:', e); process.exit(1); });
