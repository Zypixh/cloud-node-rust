use crate::config_models::{HTTPRequestCond, HTTPRequestCondGroup, HTTPRequestCondsConfig};
use pingora_proxy::Session;

impl HTTPRequestCondsConfig {
    pub fn match_request_with_scheme(&self, session: &Session, scheme: &str) -> bool {
        let ctx = crate::cache::compiled::CacheEvalContext::new(session, scheme);
        self.match_request_with_context(&ctx)
    }

    pub fn request_match_with_context(
        &self,
        ctx: &crate::cache::compiled::CacheEvalContext<'_>,
    ) -> crate::cache::compiled::CacheMatchResult {
        if !self.is_on || self.groups.is_empty() {
            return crate::cache::compiled::CacheMatchResult::Match;
        }

        if self.connector == "and" {
            let mut deferred = false;
            for group in &self.groups {
                match group.request_match_with_context(ctx) {
                    crate::cache::compiled::CacheMatchResult::Match => {}
                    crate::cache::compiled::CacheMatchResult::Deferred => deferred = true,
                    crate::cache::compiled::CacheMatchResult::NoMatch => {
                        return crate::cache::compiled::CacheMatchResult::NoMatch;
                    }
                }
            }
            if deferred {
                crate::cache::compiled::CacheMatchResult::Deferred
            } else {
                crate::cache::compiled::CacheMatchResult::Match
            }
        } else {
            let mut deferred = false;
            for group in &self.groups {
                match group.request_match_with_context(ctx) {
                    crate::cache::compiled::CacheMatchResult::Match => {
                        return crate::cache::compiled::CacheMatchResult::Match;
                    }
                    crate::cache::compiled::CacheMatchResult::Deferred => deferred = true,
                    crate::cache::compiled::CacheMatchResult::NoMatch => {}
                }
            }
            if deferred {
                crate::cache::compiled::CacheMatchResult::Deferred
            } else {
                crate::cache::compiled::CacheMatchResult::NoMatch
            }
        }
    }

    pub fn match_request_with_context(
        &self,
        ctx: &crate::cache::compiled::CacheEvalContext<'_>,
    ) -> bool {
        if !self.is_on || self.groups.is_empty() {
            return true;
        }

        if self.connector == "and" {
            self.groups
                .iter()
                .all(|group| group.match_request_with_context(ctx))
        } else {
            self.groups
                .iter()
                .any(|group| group.match_request_with_context(ctx))
        }
    }
}

impl HTTPRequestCondGroup {
    pub fn match_request_with_scheme(&self, session: &Session, scheme: &str) -> bool {
        let ctx = crate::cache::compiled::CacheEvalContext::new(session, scheme);
        self.match_request_with_context(&ctx)
    }

    pub fn request_match_with_context(
        &self,
        ctx: &crate::cache::compiled::CacheEvalContext<'_>,
    ) -> crate::cache::compiled::CacheMatchResult {
        if !self.is_on || self.conds.is_empty() {
            return crate::cache::compiled::CacheMatchResult::Match;
        }

        if self.connector == "and" {
            let mut deferred = false;
            for cond in &self.conds {
                match cond.request_match_with_context(ctx) {
                    crate::cache::compiled::CacheMatchResult::Match => {}
                    crate::cache::compiled::CacheMatchResult::Deferred => deferred = true,
                    crate::cache::compiled::CacheMatchResult::NoMatch => {
                        return crate::cache::compiled::CacheMatchResult::NoMatch;
                    }
                }
            }
            if deferred {
                crate::cache::compiled::CacheMatchResult::Deferred
            } else {
                crate::cache::compiled::CacheMatchResult::Match
            }
        } else {
            let mut deferred = false;
            for cond in &self.conds {
                match cond.request_match_with_context(ctx) {
                    crate::cache::compiled::CacheMatchResult::Match => {
                        return crate::cache::compiled::CacheMatchResult::Match;
                    }
                    crate::cache::compiled::CacheMatchResult::Deferred => deferred = true,
                    crate::cache::compiled::CacheMatchResult::NoMatch => {}
                }
            }
            if deferred {
                crate::cache::compiled::CacheMatchResult::Deferred
            } else {
                crate::cache::compiled::CacheMatchResult::NoMatch
            }
        }
    }

    pub fn match_request_with_context(
        &self,
        ctx: &crate::cache::compiled::CacheEvalContext<'_>,
    ) -> bool {
        if !self.is_on || self.conds.is_empty() {
            return true;
        }

        if self.connector == "and" {
            self.conds
                .iter()
                .all(|cond| cond.match_request_with_context(ctx))
        } else {
            self.conds
                .iter()
                .any(|cond| cond.match_request_with_context(ctx))
        }
    }
}

impl HTTPRequestCond {
    pub fn match_request_with_scheme(&self, session: &Session, scheme: &str) -> bool {
        let ctx = crate::cache::compiled::CacheEvalContext::new(session, scheme);
        self.match_request_with_context(&ctx)
    }

    pub fn request_match_with_context(
        &self,
        ctx: &crate::cache::compiled::CacheEvalContext<'_>,
    ) -> crate::cache::compiled::CacheMatchResult {
        let variable = crate::cache::compiled::CacheVariable::compile(&self.param);
        if !self.is_request || variable.is_response_known() {
            return crate::cache::compiled::CacheMatchResult::Deferred;
        }
        crate::cache::compiled::CacheMatchResult::from_bool(self.match_request_with_context(ctx))
    }

    pub fn match_request_with_context(
        &self,
        ctx: &crate::cache::compiled::CacheEvalContext<'_>,
    ) -> bool {
        let param_value = get_variable_value_with_context(ctx, &self.param);
        let expected = self.value.as_str();
        let matched = crate::cache::compiled::CacheOperator::compile(
            &self.operator,
            expected,
            self.is_case_insensitive,
        )
        .matches_with_context(&param_value, ctx);

        if self.is_reverse { !matched } else { matched }
    }
}

pub fn get_variable_value_with_scheme(session: &Session, param: &str, scheme: &str) -> String {
    let ctx = crate::cache::compiled::CacheEvalContext::new(session, scheme);
    get_variable_value_with_context(&ctx, param)
}

pub fn get_variable_value_with_context(
    ctx: &crate::cache::compiled::CacheEvalContext<'_>,
    param: &str,
) -> String {
    if let Some(inner) = param
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
    {
        return crate::cache::compiled::CacheVariable::compile_inner(inner).resolve_with_context(ctx);
    }

    param.to_string()
}


pub fn format_variables_with_scheme(session: &Session, template: &str, scheme: &str) -> String {
    let ctx = crate::cache::compiled::CacheEvalContext::new(session, scheme);
    format_variables_with_context(&ctx, template)
}

pub fn format_variables_with_context(
    ctx: &crate::cache::compiled::CacheEvalContext<'_>,
    template: &str,
) -> String {
    let Some(mut search_start) = template.find("${") else {
        return template.to_string();
    };

    let mut result = String::with_capacity(template.len());
    let mut literal_start = 0;
    loop {
        result.push_str(&template[literal_start..search_start]);
        let expr_start = search_start + 2;
        let Some(end_offset) = template[expr_start..].find('}') else {
            result.push_str(&template[search_start..]);
            return result;
        };
        let expr_end = expr_start + end_offset + 1;
        result.push_str(&get_variable_value_with_context(
            ctx,
            &template[search_start..expr_end],
        ));
        literal_start = expr_end;
        let Some(next_offset) = template[literal_start..].find("${") else {
            result.push_str(&template[literal_start..]);
            return result;
        };
        search_start = literal_start + next_offset;
    }
}
