//! Fee Distribution Constants — Spec §9.2
//!
//! Distribusi fee per transaksi:
//!   Relay pool    : 70%  — proporsional txn_relayed × uptime_weight
//!   Aggregator    : 25%  — proporsional batch_value (jika Proof-of-Inclusion valid)
//!   Security fund :  5%  — protocol reserve (bug bounty, audit, emergency)
//!
//! Jika aggregator tidak bisa prove Proof-of-Inclusion:
//!   25% aggregator hangus → masuk relay pool (spec §9.2).
//!
//! OSSIFIED: split 70/25/5 tidak bisa diubah tanpa hard fork.

/// Persentase fee untuk relay pool. OSSIFIED — spec §9.2.
/// Basis: 100 (persen). Sisa pembulatan integer masuk ke relay.
pub const RELAY_PERCENT: u64 = 70;

/// Persentase fee untuk aggregator pool. OSSIFIED — spec §9.2.
/// Hanya dibayar jika Proof-of-Inclusion valid.
pub const AGGREGATOR_PERCENT: u64 = 25;

/// Persentase fee untuk security fund. OSSIFIED — spec §9.2.
/// Protocol reserve: bug bounty, audit, emergency response.
pub const SECURITY_FUND_PERCENT: u64 = 5;

/// Invariant: ketiga persentase harus berjumlah tepat 100.
/// Dicek di compile time via const assertion.
const _: () = assert!(
    RELAY_PERCENT + AGGREGATOR_PERCENT + SECURITY_FUND_PERCENT == 100,
    "Fee split harus berjumlah 100% — spec §9.2"
);

/// Hasil distribusi fee untuk satu transaksi atau satu batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeDistribution {
    /// Bagian relay pool (70%). Spec §9.2.
    pub relay: u64,
    /// Bagian aggregator pool (25%). Spec §9.2.
    /// Set ke 0 jika Proof-of-Inclusion gagal — hangus ke relay.
    pub aggregator: u64,
    /// Bagian security fund (5%). Spec §9.2.
    pub security_fund: u64,
}

/// Hitung distribusi fee dari total fee. Spec §9.2.
///
/// Pembulatan: aggregator dan security dihitung integer division,
/// sisa pembulatan masuk relay (tidak ada token yang hilang).
///
/// `proof_of_inclusion_valid`: jika false, aggregator share = 0
/// dan bagiannya ditambahkan ke relay (spec §9.2).
pub fn distribute_fee(fee_total: u64, proof_of_inclusion_valid: bool) -> FeeDistribution {
    let agg_raw = fee_total * AGGREGATOR_PERCENT / 100;
    let sec = fee_total * SECURITY_FUND_PERCENT / 100;

    let aggregator = if proof_of_inclusion_valid { agg_raw } else { 0 };
    // Relay mendapat sisa — memastikan relay + aggregator + security = fee_total
    let relay = fee_total.saturating_sub(aggregator).saturating_sub(sec);

    FeeDistribution {
        relay,
        aggregator,
        security_fund: sec,
    }
}

/// Verifikasi bahwa distribusi tidak kehilangan atau menciptakan token.
/// relay + aggregator + security_fund == fee_total.
pub fn distribution_is_conserved(dist: &FeeDistribution, fee_total: u64) -> bool {
    dist.relay
        .saturating_add(dist.aggregator)
        .saturating_add(dist.security_fund)
        == fee_total
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constant correctness ──────────────────────────────────────────────────

    #[test]
    fn test_relay_percent_is_70() {
        // Spec §9.2: relay pool = 70%. OSSIFIED.
        assert_eq!(RELAY_PERCENT, 70);
    }

    #[test]
    fn test_aggregator_percent_is_25() {
        // Spec §9.2: aggregator pool = 25%. OSSIFIED.
        assert_eq!(AGGREGATOR_PERCENT, 25);
    }

    #[test]
    fn test_security_fund_percent_is_5() {
        // Spec §9.2: security fund = 5%. OSSIFIED.
        assert_eq!(SECURITY_FUND_PERCENT, 5);
    }

    #[test]
    fn test_split_sums_to_100() {
        // Invariant: 70 + 25 + 5 = 100. Spec §9.2.
        assert_eq!(
            RELAY_PERCENT + AGGREGATOR_PERCENT + SECURITY_FUND_PERCENT,
            100
        );
    }

    // ── Distribution correctness ──────────────────────────────────────────────

    #[test]
    fn test_distribution_100_sscl_valid_poi() {
        // 100 sSCL: relay=70, agg=25, sec=5
        let d = distribute_fee(100, true);
        assert_eq!(d.relay, 70);
        assert_eq!(d.aggregator, 25);
        assert_eq!(d.security_fund, 5);
    }

    #[test]
    fn test_distribution_invalid_poi_aggregator_zero() {
        // Proof-of-Inclusion gagal → aggregator=0, relay dapat bagian agg
        let d = distribute_fee(100, false);
        assert_eq!(d.aggregator, 0);
        assert_eq!(d.security_fund, 5);
        assert_eq!(d.relay, 95); // 70 + 25 dari agg yang hangus
    }

    #[test]
    fn test_distribution_conserved_valid_poi() {
        let fee = 1_000_000;
        let d = distribute_fee(fee, true);
        assert!(
            distribution_is_conserved(&d, fee),
            "Token harus conserved: relay+agg+sec == fee_total"
        );
    }

    #[test]
    fn test_distribution_conserved_invalid_poi() {
        let fee = 1_000_000;
        let d = distribute_fee(fee, false);
        assert!(distribution_is_conserved(&d, fee));
    }

    #[test]
    fn test_distribution_zero_fee() {
        let d = distribute_fee(0, true);
        assert_eq!(d.relay, 0);
        assert_eq!(d.aggregator, 0);
        assert_eq!(d.security_fund, 0);
    }

    #[test]
    fn test_distribution_rounding_no_token_loss() {
        // Fee = 1 sSCL: agg=0 (floor(1×25/100)), sec=0 (floor(1×5/100))
        // relay = 1 - 0 - 0 = 1 (sisa pembulatan ke relay)
        let d = distribute_fee(1, true);
        assert!(distribution_is_conserved(&d, 1));
        assert_eq!(d.relay + d.aggregator + d.security_fund, 1);
    }

    #[test]
    fn test_distribution_large_fee_conserved() {
        // Uji dengan nilai besar mendekati u64 boundary
        let fee = 1_000_000_000_000u64; // 1 triliun sSCL
        let d = distribute_fee(fee, true);
        assert!(distribution_is_conserved(&d, fee));
    }

    #[test]
    fn test_no_floating_point() {
        // Semua kalkulasi murni integer — tidak ada f32/f64
        let d = distribute_fee(40, true);
        // 40 sSCL: agg=10, sec=2, relay=28
        assert_eq!(d.aggregator, 10);
        assert_eq!(d.security_fund, 2);
        assert_eq!(d.relay, 28);
        assert!(distribution_is_conserved(&d, 40));
    }
}
