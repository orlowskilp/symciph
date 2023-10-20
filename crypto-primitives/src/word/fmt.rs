use super::Word;
use std::fmt::{Debug, Display};

impl Display for Word {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:064b}", self.value)
    }
}

impl Debug for Word {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:064b}", self.value))
    }
}
