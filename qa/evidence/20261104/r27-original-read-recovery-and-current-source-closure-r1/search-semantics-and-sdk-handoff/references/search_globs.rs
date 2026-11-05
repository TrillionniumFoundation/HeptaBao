// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Compile bounded ripgrep override globs once into byte regexes for the private worker.
use anyhow::{bail, Context, Result};
use globset::GlobBuilder;
use ignore::overrides::OverrideBuilder;
use serde::Serialize;

use super::{SearchKind, SearchQueryMode, SearchStartParams};

#[derive(Debug, Serialize)]
pub(super) struct GlobRule {
	regex: String,
	include: bool,
	only_dir: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct GlobProgram {
	version: u8,
	file_rules: Vec<GlobRule>,
	exclude_rules: Vec<GlobRule>,
	query_rules: Option<Vec<GlobRule>>,
}

fn compile_rule(pattern: &str, insensitive: bool, exclude: bool) -> Result<Option<GlobRule>> {
	// Validate with the exact override parser ripgrep uses before translating its
	// documented anchoring/directory rules into the same underlying glob compiler.
	let mut validator = OverrideBuilder::new("");
	validator.case_insensitive(insensitive)?.add(pattern)?;
	validator.build()?;
	let pattern = if pattern.ends_with("\\ ") {
		pattern
	} else {
		pattern.trim_end()
	};
	if pattern.starts_with('#') || pattern.is_empty() {
		return Ok(None);
	}
	let mut body = pattern;
	let mut negative = false;
	let mut anchored = false;
	if body.starts_with("\\!") || body.starts_with("\\#") {
		body = &body[1..];
	} else {
		if let Some(rest) = body.strip_prefix('!') {
			negative = true;
			body = rest;
		}
		if let Some(rest) = body.strip_prefix('/') {
			anchored = true;
			body = rest;
		}
	}
	let only_dir = body.ends_with('/');
	if only_dir {
		body = &body[..body.len() - 1];
		if body.ends_with('\\') {
			body = &body[..body.len() - 1];
		}
	}
	let mut actual = if !anchored && !body.contains('/') && !body.starts_with("**/") {
		format!("**/{body}")
	} else {
		body.to_owned()
	};
	if actual.ends_with("/**") {
		actual.push_str("/*");
	}
	let glob = GlobBuilder::new(&actual)
		.literal_separator(true)
		.backslash_escape(true)
		.case_insensitive(insensitive)
		.build()
		.context("invalid search glob")?;
	// globset emits an ASCII byte-regex subset (hex literals, classes, groups,
	// repetitions and ASCII case folding). Python bytes regexes use these same
	// constructs; its unsupported Unicode-disable prefix is unnecessary for bytes.
	let regex = glob
		.regex()
		.strip_prefix("(?-u)")
		.ok_or_else(|| anyhow::anyhow!("unsupported compiled search glob syntax"))?;
	if !regex.is_ascii() {
		bail!("unsupported non-byte search glob syntax");
	}
	Ok(Some(GlobRule {
		regex: regex.into(),
		include: negative == exclude,
		only_dir,
	}))
}

pub(super) fn compile_glob_program(params: &SearchStartParams) -> Result<GlobProgram> {
	let mut file_rules = Vec::new();
	if let Some(patterns) = &params.file_pattern {
		for pattern in patterns
			.split('|')
			.map(str::trim)
			.filter(|part| !part.is_empty())
		{
			if let Some(rule) = compile_rule(pattern, params.ignore_case, false)? {
				file_rules.push(rule);
			}
		}
	}
	let mut exclude_rules = Vec::new();
	for pattern in &params.exclude_patterns {
		if let Some(rule) = compile_rule(pattern, params.ignore_case, true)? {
			exclude_rules.push(rule);
		}
	}
	let query_rules = if matches!(params.query_mode, Some(SearchQueryMode::Glob)) {
		if !matches!(params.kind, SearchKind::Files) {
			bail!("glob query mode requires a file search");
		}
		Some(
			compile_rule(&params.query, params.ignore_case, false)?
				.into_iter()
				.collect(),
		)
	} else {
		None
	};
	let program = GlobProgram {
		version: 1,
		file_rules,
		exclude_rules,
		query_rules,
	};
	if serde_json::to_vec(&program)?.len() > 128 * 1024 {
		bail!("compiled search globs exceed 128 KiB");
	}
	Ok(program)
}
