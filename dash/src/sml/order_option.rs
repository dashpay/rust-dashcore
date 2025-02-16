#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct LLMQOrderOption {
    pub reverse_sort_scores: bool,
    pub reverse_sort_order: bool,
}

impl LLMQOrderOption {
    pub fn all_combinations() -> Vec<LLMQOrderOption> {
        let mut combinations = Vec::with_capacity(8);

        for reverse_sort_scores in [false, true] {
            for reverse_sort_order in [false, true] {
                combinations.push(LLMQOrderOption {
                    reverse_sort_scores,
                    reverse_sort_order,
                });
            }
        }

        combinations
    }
}