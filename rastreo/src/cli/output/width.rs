use rastreo_core::encoder::table::default_width;

pub(crate) fn stdout_table_width() -> u16 {
    table_width(terminal_size::terminal_size_of(std::io::stdout()).map(|(width, _)| width.0))
}

// A redirected stdout has no width to read and no knowable consumer, so the grid is fixed instead.
fn table_width(measured: Option<u16>) -> u16 {
    measured.unwrap_or_else(default_width)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_measured_terminal_sets_the_grid_width() {
        assert_eq!(table_width(Some(200)), 200);
    }

    #[test]
    fn an_unmeasurable_stdout_falls_back_to_the_encoder_default() {
        assert_eq!(table_width(None), default_width());
    }

    #[test]
    fn a_narrow_terminal_is_passed_through_for_the_layout_to_clamp() {
        assert_eq!(table_width(Some(20)), 20);
    }
}
