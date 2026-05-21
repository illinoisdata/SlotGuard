use slotguard_core::detect_credentials;

fn main() {
    let github_token = ["ghp_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"].concat();
    let private_key = [
        "-----BEGIN",
        " PRIVATE KEY-----\n",
        "AAAA\n",
        "BBBB\n",
        "-----END",
        " PRIVATE KEY-----",
    ]
    .concat();
    let cases = vec![
        format!("API_KEY={github_token}"),
        "DATABASE_URL=postgres://app:hunter2pass1234@db-1234.acme-corp.example/prod".to_string(),
        "OAUTH_TOKEN=xoxb-AAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        "OWNER_EMAIL=alice.4qq2@acme-corp.example".to_string(),
        "INTERNAL_HOST=vault-abcd.internal.acme-corp.example".to_string(),
        format!("PRIVATE_KEY={private_key}"),
    ];
    for case in cases {
        let hits = detect_credentials(&case);
        println!("INPUT: {}", case.split('\n').next().unwrap_or(&case));
        println!("  hits: {}", hits.len());
        for hit in hits {
            println!(
                "    [{}] {}",
                hit.category.label(),
                &hit.raw_value[..hit.raw_value.len().min(40)]
            );
        }
    }
}
