/// Controls how strictly the engine enforces the scripted command sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioMode {
    /// Reject mismatched commands and report the expected command.
    Strict,
    /// Allow mismatched commands to fall back without advancing the script.
    Lenient,
}

/// One scripted command/response pair in a scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioStep {
    /// The exact command that must match this step.
    pub expect_command: String,
    /// Optional XML to return when the command matches this step.
    pub respond_xml: Option<String>,
}

/// Result of evaluating a command against the current scenario state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScenarioOutcome {
    /// Returns the scripted XML response for a matched step.
    Scripted(String),
    /// Indicates the caller should use the non-scripted fallback behavior.
    Fallback,
    /// Reports a strict-mode command mismatch without consuming the step.
    StrictMismatch {
        /// The command that was expected for the current step.
        expected: String,
        /// The command that was actually received.
        got: String,
    },
    /// Indicates that no scripted steps remain to evaluate.
    Exhausted,
}

/// Tracks progress through a scripted sequence of mock server interactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioEngine {
    mode: ScenarioMode,
    steps: Vec<ScenarioStep>,
    cursor: usize,
}

impl ScenarioEngine {
    /// Creates a new engine for the given mode and scripted steps.
    pub fn new(mode: ScenarioMode, steps: Vec<ScenarioStep>) -> Self {
        Self {
            mode,
            steps,
            cursor: 0,
        }
    }

    /// Returns `true` when there are no remaining scripted steps to consume.
    pub fn is_exhausted(&self) -> bool {
        self.steps.is_empty() || self.cursor >= self.steps.len()
    }

    /// Evaluates a command against the current step and advances on a match.
    pub fn next_for_command(&mut self, command: &str) -> ScenarioOutcome {
        if self.steps.is_empty() || self.cursor >= self.steps.len() {
            return ScenarioOutcome::Exhausted;
        }

        let step = &self.steps[self.cursor];
        if command == step.expect_command {
            self.cursor += 1;
            return match &step.respond_xml {
                Some(xml) => ScenarioOutcome::Scripted(xml.clone()),
                None => ScenarioOutcome::Fallback,
            };
        }

        match self.mode {
            ScenarioMode::Strict => ScenarioOutcome::StrictMismatch {
                expected: step.expect_command.clone(),
                got: command.to_string(),
            },
            ScenarioMode::Lenient => ScenarioOutcome::Fallback,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ScenarioEngine, ScenarioMode, ScenarioOutcome, ScenarioStep,
    };

    fn step(expect_command: &str, respond_xml: Option<&str>) -> ScenarioStep {
        ScenarioStep {
            expect_command: expect_command.to_string(),
            respond_xml: respond_xml.map(str::to_string),
        }
    }

    #[test]
    fn exact_sequence_strict() {
        let mut engine = ScenarioEngine::new(
            ScenarioMode::Strict,
            vec![step("one", Some("<one/>")), step("two", Some("<two/>"))],
        );

        assert_eq!(
            engine.next_for_command("one"),
            ScenarioOutcome::Scripted("<one/>".to_string())
        );
        assert_eq!(
            engine.next_for_command("two"),
            ScenarioOutcome::Scripted("<two/>".to_string())
        );
        assert!(engine.is_exhausted());
    }

    #[test]
    fn mismatch_strict() {
        let mut engine = ScenarioEngine::new(ScenarioMode::Strict, vec![step("expected", None)]);

        assert_eq!(
            engine.next_for_command("actual"),
            ScenarioOutcome::StrictMismatch {
                expected: "expected".to_string(),
                got: "actual".to_string(),
            }
        );
    }

    #[test]
    fn mismatch_lenient_keeps_cursor() {
        let mut engine = ScenarioEngine::new(
            ScenarioMode::Lenient,
            vec![step("expected", Some("<ok/>"))],
        );

        assert_eq!(engine.next_for_command("wrong"), ScenarioOutcome::Fallback);
        assert!(!engine.is_exhausted());
        assert_eq!(
            engine.next_for_command("expected"),
            ScenarioOutcome::Scripted("<ok/>".to_string())
        );
    }

    #[test]
    fn exhausted_behavior() {
        let mut engine = ScenarioEngine::new(ScenarioMode::Strict, vec![step("only", None)]);

        assert_eq!(engine.next_for_command("only"), ScenarioOutcome::Fallback);
        assert!(engine.is_exhausted());
        assert_eq!(engine.next_for_command("only"), ScenarioOutcome::Exhausted);
    }

    #[test]
    fn empty_scenario_exhausted() {
        let mut engine = ScenarioEngine::new(ScenarioMode::Strict, Vec::new());

        assert!(engine.is_exhausted());
        assert_eq!(engine.next_for_command("anything"), ScenarioOutcome::Exhausted);
    }

    #[test]
    fn scripted_response_returned() {
        let mut engine = ScenarioEngine::new(
            ScenarioMode::Strict,
            vec![step("cmd", Some("<response/>"))],
        );

        assert_eq!(
            engine.next_for_command("cmd"),
            ScenarioOutcome::Scripted("<response/>".to_string())
        );
    }

    #[test]
    fn fallback_when_respond_xml_none() {
        let mut engine = ScenarioEngine::new(ScenarioMode::Strict, vec![step("cmd", None)]);

        assert_eq!(engine.next_for_command("cmd"), ScenarioOutcome::Fallback);
    }

    #[test]
    fn lenient_then_later_correct_step_works() {
        let mut engine = ScenarioEngine::new(
            ScenarioMode::Lenient,
            vec![step("first", Some("<first/>")), step("second", Some("<second/>"))],
        );

        assert_eq!(engine.next_for_command("wrong"), ScenarioOutcome::Fallback);
        assert_eq!(
            engine.next_for_command("first"),
            ScenarioOutcome::Scripted("<first/>".to_string())
        );
        assert_eq!(
            engine.next_for_command("second"),
            ScenarioOutcome::Scripted("<second/>".to_string())
        );
    }

    #[test]
    fn strict_mismatch_does_not_advance_cursor() {
        let mut engine = ScenarioEngine::new(
            ScenarioMode::Strict,
            vec![step("first", Some("<first/>"))],
        );

        assert_eq!(
            engine.next_for_command("wrong"),
            ScenarioOutcome::StrictMismatch {
                expected: "first".to_string(),
                got: "wrong".to_string(),
            }
        );
        assert!(!engine.is_exhausted());
        assert_eq!(
            engine.next_for_command("first"),
            ScenarioOutcome::Scripted("<first/>".to_string())
        );
    }
}
