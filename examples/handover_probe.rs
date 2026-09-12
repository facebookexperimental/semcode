// SPDX-License-Identifier: MIT OR Apache-2.0
//
// How often a call that is handed a function turns out to install it, and
// where the follow gives up.
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

use semcode::DatabaseManager;

#[tokio::main]
async fn main() -> Result<()> {
    let db_path = std::env::args().nth(1).unwrap();
    let repo = std::env::args().nth(2).unwrap();
    let git_sha = std::env::args().nth(3).unwrap();

    let db = Arc::new(DatabaseManager::new(&db_path, repo).await?);

    // One attempt per registrar position, not per call site: the answer is a
    // fact about the callee.
    let mut positions: HashMap<(String, u32), usize> = HashMap::new();
    for row in db.all_argument_functions().await? {
        *positions
            .entry((row.callee.clone(), row.argument_index))
            .or_default() += 1;
    }
    println!("distinct (callee, argument) positions: {}", positions.len());

    let mut ranked: Vec<_> = positions.into_iter().collect();
    ranked.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

    let sample = std::env::args()
        .nth(4)
        .and_then(|n| n.parse().ok())
        .unwrap_or(400)
        .min(ranked.len());
    let mut function_valued = 0usize;
    let mut unresolved: Vec<String> = Vec::new();
    let mut resolved = 0usize;
    let mut resolved_sites = 0usize;
    let mut disagreeing = 0usize;
    let mut sites = 0usize;
    let mut examples = Vec::new();
    for ((callee, index), count) in ranked.iter().take(sample) {
        sites += count;
        // Only a position that takes a function can install one.
        let takes_a_function = match db.find_function_git_aware(callee, &git_sha).await? {
            Some(function) => match function.parameters.get(*index as usize) {
                Some(parameter) => {
                    db.type_is_function_pointer(&parameter.type_name, &git_sha)
                        .await?
                }
                None => false,
            },
            None => false,
        };
        if !takes_a_function {
            continue;
        }
        function_valued += 1;

        // Every definition of the name is walked now, so a name can produce
        // more than one claim. Two claims about one handover is a finding in
        // its own right, so they are counted apart from the agreeing ones.
        let handovers = db.follow_handed_parameter(callee, *index, &git_sha).await?;
        if !handovers.is_empty() {
            resolved += 1;
            resolved_sites += count;
            if handovers.len() > 1 {
                disagreeing += 1;
            }
            if examples.len() < 10 {
                let (handover, agreeing) = &handovers[0];
                examples.push(match handover {
                    semcode::Handover::StoredIn {
                        path,
                        container_type,
                        member,
                    } => format!(
                        "{callee}[{index}] -> {container_type}::{member} via {} ({agreeing} agree, {} claims)",
                        path.join(" -> "),
                        handovers.len()
                    ),
                    semcode::Handover::Invoked { path } => {
                        format!("{callee}[{index}] -> called, via {} ({agreeing} agree)", path.join(" -> "))
                    }
                });
            }
        } else if unresolved.len() < 12 {
            let function = db.find_function_git_aware(callee, &git_sha).await?.unwrap();
            let parameter = function.parameters[*index as usize].name.clone();
            let fates = semcode::TreeSitterAnalyzer::parameter_fate(&function.body, &parameter);
            unresolved.push(format!("{callee}[{index}] ({count} sites): {fates:?}"));
        }
    }
    println!("of the {sample} busiest positions ({sites} call sites):");
    println!("  take a function at that position: {function_valued}");
    println!("  reach a member: {resolved} positions, {resolved_sites} sites");
    println!("  positions whose definitions disagree about where it goes: {disagreeing}");
    for example in examples {
        println!("    {example}");
    }
    println!("  give up, and what the body showed:");
    for line in unresolved {
        println!("    {line}");
    }
    Ok(())
}
