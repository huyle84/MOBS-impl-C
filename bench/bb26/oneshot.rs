// One-shot timing of the BB26 blind signature (Table 4 configuration), for a
// same-machine comparison with MOBS. Usage: oneshot <runs> <masked|hashed>
use blind_mldsa::{BlindMLDSA, CommitmentMode, IssuerHidingMode::NoHiding, MLDSALengthCheck::ThreeBits,
                  ORAMMode::GeneralORAM, ShakeSegmentPlan};
use merlin::Transcript;
use ml_dsa::{KeyInit, Keypair, MlDsa44, Seed, Signer, SigningKey, KeyExport};
use rand::thread_rng;
use schmivitz::{parameters::FullFieldMaskMethod, proof::EdabitVariant};
fn run() {
    let args: Vec<String> = std::env::args().collect();
    let runs: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(1);
    let mode = if args.get(2).map(|s| s.as_str()) == Some("hashed") { CommitmentMode::Hashed } else { CommitmentMode::Masked };
    let blind = BlindMLDSA { version: ThreeBits, oram_mode: GeneralORAM, maximal_iterations_oram: 213,
        segment_plan: ShakeSegmentPlan::Fwd3, commitment_type: mode, issuer_hiding_mode: NoHiding,
        mask_method: FullFieldMaskMethod::Crt, edabit_variant: EdabitVariant::ExponentCheck };
    let transcript = Transcript::new(b"Happy Benchmarking.");
    let mut seed = Seed::default(); seed.copy_from_slice(&[7u8; 32]);
    let sk = SigningKey::<MlDsa44>::new(&seed);
    let vk = sk.verifying_key().to_bytes().to_vec();
    let message = "We benchmarks our blind mldsa construction.";
    let mut rng = thread_rng();
    for r in 0..runs {
        let t = std::time::Instant::now();
        let (st, com) = blind.compute_commitment(message.to_owned(), &mut transcript.clone(), &mut thread_rng());
        let tc = t.elapsed().as_secs_f64() * 1e3;
        let sig = sk.sign(&com).encode().to_vec();
        let t = std::time::Instant::now();
        let (proof, inputs) = blind.prove(st, &vk, &sig, &com, &mut transcript.clone(), &mut rng).expect("prove");
        let tp = t.elapsed().as_secs_f64() * 1e3;
        let t = std::time::Instant::now();
        blind.verify(&proof, &inputs.public_f2, &inputs.public_fq, &mut transcript.clone()).expect("verify");
        let tv = t.elapsed().as_secs_f64() * 1e3;
        println!("run={} mode={:?} commit_ms={:.2} prove_ms={:.2} verify_ms={:.2} proof_bytes={}", r, mode, tc, tp, tv, proof.proof_size_estimate());
    }
}
fn main() {
    std::thread::Builder::new().stack_size(1 << 30).spawn(run).unwrap().join().unwrap();
}
