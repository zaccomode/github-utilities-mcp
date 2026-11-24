/**
 * Which GitHub Actions workflows a release change will start.
 *
 * `publish_release` and `promote_release` show this in their previews, so the
 * person approving can see the deploys and package publishes that follow.
 * Workflow files are parsed with a real YAML parser; only the top-level `on:`
 * and `name:` are read.
 *
 * Every gap fails safe: a file that cannot be read or parsed is listed as
 * unanalysed (it may still run), never silently dropped.
 */

import { isScalar, parseDocument } from "yaml";
import { GitHubError, type Repo, type TokenSource, gh, repoPath } from "./client";

/** How many workflow files a report reads before giving up. */
export const MAX_WORKFLOW_FILES = 20;

/**
 * The `release` activity types GitHub sends.
 * https://docs.github.com/actions/reference/events-that-trigger-workflows#release
 */
export type ReleaseAction =
	| "published"
	| "unpublished"
	| "created"
	| "edited"
	| "deleted"
	| "prereleased"
	| "released";

export interface WorkflowRef {
	path: string;
	name?: string;
}

export interface WorkflowReport {
	/** Workflow files whose `on: release` matches one of the actions sent. */
	triggered_by_release: WorkflowRef[];
	/**
	 * Workflow files that start because the change creates the tag: `create`,
	 * or `push` with a tag filter or no ref filter. Only set when the tag does
	 * not exist yet.
	 */
	triggered_by_tag_creation?: WorkflowRef[];
	/**
	 * Workflow files with `on: workflow_run` naming one of the workflows above,
	 * directly or through a chain of them. GitHub runs `workflow_run` workflows
	 * from the default branch, so these are read there, not at the ref.
	 */
	triggered_by_workflow_run?: WorkflowRef[];
	/**
	 * Default-branch `workflow_run` workflows that wait for a workflow this
	 * report could not identify. Only set when some workflow at the ref could
	 * not be analysed: it may be the one they wait for, so they may run.
	 */
	possibly_triggered_by_workflow_run?: WorkflowRef[];
	/** Default-branch workflow files that could not be read or parsed. */
	unanalysed_on_default_branch?: string[];
	/** Default-branch workflow files past the read limit. */
	unchecked_files_on_default_branch?: string[];
	/**
	 * Set when the default branch's workflows could not be listed, so which
	 * `workflow_run` workflows follow is unknown.
	 */
	default_branch_unreadable?: true;
	/**
	 * Workflow files that could not be read or parsed. Whether they run is
	 * unknown — GitHub's parser may accept what this one rejects — so they are
	 * reported, and bound into the confirm token, as possibly starting.
	 */
	unanalysed?: string[];
	/** The `release` activity types this change sends. */
	release_actions: ReleaseAction[];
	files_checked: number;
	/** Set when there were more files than were read. */
	unchecked_files?: string[];
	note?: string;
}

interface GitHubContent {
	type: string;
	name: string;
	path: string;
	/** The blob's git SHA; equal SHAs mean equal contents. */
	sha?: string;
	content?: string;
}

interface ParsedWorkflow {
	name?: string;
	events: Map<string, unknown>;
}

/**
 * Parses a workflow file's `name:` and the events its top-level `on:` names,
 * each with its settings (null when it has none). Returns undefined for a file
 * this parser cannot read: invalid YAML, or one that trips the parser's limits
 * (such as its cap on alias expansion). GitHub's own parser may still accept
 * it, so callers must treat undefined as "unknown", not "will not run".
 *
 * `on:` may be a scalar (`on: release`), a sequence (`on: [push, release]`) or
 * a mapping of events to their settings, in block or flow style.
 */
export function parseWorkflow(yaml: string): ParsedWorkflow | undefined {
	let root: unknown;
	let name: string | undefined;
	try {
		const doc = parseDocument(yaml.replace(/^\uFEFF/, ""));
		if (doc.errors.length) {
			return undefined;
		}
		// toJS throws, rather than reporting an error, past maxAliasCount.
		root = doc.toJS();
		name = workflowName(doc.get("name", true));
	} catch {
		return undefined;
	}
	if (!isRecord(root)) {
		return { events: new Map() };
	}

	const events = new Map<string, unknown>();
	const on = root.on;
	if (typeof on === "string") {
		events.set(on, null);
	} else if (Array.isArray(on)) {
		for (const event of on) {
			if (typeof event === "string") {
				events.set(event, null);
			}
		}
	} else if (isRecord(on)) {
		for (const [event, settings] of Object.entries(on)) {
			events.set(event, settings ?? null);
		}
	}

	return { name, events };
}

/**
 * A workflow's `name:` as GitHub sees it. A non-string scalar (`name: 1.0`,
 * `name: true`) is still a name; GitHub reads it as its source text, so that
 * is used rather than the parsed number, which would turn `1.0` into `1`.
 */
function workflowName(node: unknown): string | undefined {
	if (!isScalar(node) || node.value === null || node.value === undefined) {
		return undefined;
	}
	if (typeof node.value === "string") {
		return node.value;
	}
	return node.source || String(node.value);
}

/**
 * The workflow names an `on: workflow_run` trigger waits for, or undefined
 * when the workflow has none. GitHub requires `workflows:`; a scalar counts as
 * a single name.
 */
export function workflowRunSources(workflow: ParsedWorkflow): string[] | undefined {
	if (!workflow.events.has("workflow_run")) {
		return undefined;
	}
	const settings = workflow.events.get("workflow_run");
	const names = isRecord(settings) ? settings.workflows : undefined;
	if (typeof names === "string") {
		return [names];
	}
	return Array.isArray(names) ? names.filter((n): n is string => typeof n === "string") : [];
}

/** GitHub follows `workflow_run` chains at most this many levels deep. */
const MAX_WORKFLOW_RUN_DEPTH = 3;

/** The name GitHub knows a workflow by: its `name:`, or else its file path. */
function workflowLabel(w: { path: string; workflow: ParsedWorkflow }): string {
	return w.workflow.name ?? w.path;
}

/**
 * The workflows in `all` that `workflow_run` would start after `started`
 * complete, following chains up to GitHub's depth limit. `all` is the default
 * branch's set and `started` comes from the ref, so a file at the same path in
 * both is still listed: the default-branch copy is a separate run.
 */
export function workflowRunChain(
	all: { path: string; workflow: ParsedWorkflow }[],
	started: { path: string; workflow: ParsedWorkflow }[],
): { path: string; workflow: ParsedWorkflow }[] {
	const seen = new Set<string>();
	const found: { path: string; workflow: ParsedWorkflow }[] = [];
	let frontier = started;
	for (let depth = 0; depth < MAX_WORKFLOW_RUN_DEPTH && frontier.length; depth++) {
		const names = new Set(frontier.map(workflowLabel));
		frontier = all.filter(
			(w) =>
				!seen.has(w.path) &&
				(workflowRunSources(w.workflow) ?? []).some((name) => names.has(name)),
		);
		for (const w of frontier) {
			seen.add(w.path);
			found.push(w);
		}
	}
	return found;
}

/** The events a workflow's top-level `on:` names, each with its settings. */
export function workflowEvents(yaml: string): Map<string, unknown> {
	return parseWorkflow(yaml)?.events ?? new Map();
}

/**
 * Whether a workflow's `on:` starts on any of these `release` activity types.
 * A `release` trigger without `types:` runs for every one of them. Without
 * `actions`, any `release` trigger counts.
 */
export function triggersOnRelease(
	yaml: string | ParsedWorkflow,
	actions?: readonly ReleaseAction[],
): boolean {
	const events = typeof yaml === "string" ? workflowEvents(yaml) : yaml.events;
	if (!events.has("release")) {
		return false;
	}
	const types = activityTypes(events.get("release"));
	return !actions || !types || actions.some((action) => types.includes(action));
}

/**
 * Whether a workflow starts when a new tag is pushed: on `create`, or on
 * `push` unless its filters name only branches. GitHub runs a `push` workflow
 * for a tag when it has a `tags`/`tags-ignore` filter, or when it has no ref
 * filter at all; `paths` filters are not applied to tags.
 */
export function triggersOnTagCreation(yaml: string | ParsedWorkflow): boolean {
	const events = typeof yaml === "string" ? workflowEvents(yaml) : yaml.events;
	if (events.has("create")) {
		return true;
	}
	if (!events.has("push")) {
		return false;
	}
	const push = events.get("push");
	if (!isRecord(push)) {
		return true;
	}
	const has = (key: string) => key in push;
	return has("tags") || has("tags-ignore") || !(has("branches") || has("branches-ignore"));
}

/** An event's `types:` filter, or undefined when it has none (every type runs). */
function activityTypes(settings: unknown): string[] | undefined {
	if (!isRecord(settings) || settings.types === undefined || settings.types === null) {
		return undefined;
	}
	const types = settings.types;
	if (typeof types === "string") {
		return [types];
	}
	return Array.isArray(types)
		? types.filter((t): t is string => typeof t === "string")
		: undefined;
}

type Parsed = { path: string; workflow: ParsedWorkflow };

interface WorkflowDir {
	parsed: Parsed[];
	unreadable: string[];
	/** Read but could not be parsed. */
	invalid: string[];
	/** Past MAX_WORKFLOW_FILES, so never read. */
	unchecked: string[];
	/** Parse results by blob SHA, so a second ref can skip unchanged files. */
	byBlob: Map<string, ParsedWorkflow | undefined>;
}

type DirResult =
	| { kind: "ok"; dir: WorkflowDir }
	| { kind: "missing" }
	| { kind: "error"; message: string };

/**
 * Reads and parses `.github/workflows` at `ref`, or on the default branch when
 * `ref` is undefined (the Contents API's default). Files whose blob SHA is in
 * `known` are not fetched again.
 */
async function readWorkflowDir(
	creds: TokenSource,
	a: Repo,
	ref: string | undefined,
	known?: Map<string, ParsedWorkflow | undefined>,
): Promise<DirResult> {
	const query = ref === undefined ? undefined : { ref };
	let entries: GitHubContent[];
	try {
		entries = await gh<GitHubContent[]>(creds, `${repoPath(a)}/contents/.github/workflows`, {
			query,
		});
	} catch (error) {
		if (error instanceof GitHubError && error.status === 404) {
			return { kind: "missing" };
		}
		return { kind: "error", message: error instanceof Error ? error.message : String(error) };
	}

	const files = (Array.isArray(entries) ? entries : []).filter(
		(entry) => entry.type === "file" && /\.ya?ml$/i.test(entry.name),
	);
	const checked = files.slice(0, MAX_WORKFLOW_FILES);
	const byBlob = new Map<string, ParsedWorkflow | undefined>();

	const results = await Promise.all(
		checked.map(async (file) => {
			if (file.sha && known?.has(file.sha)) {
				const workflow = known.get(file.sha);
				byBlob.set(file.sha, workflow);
				return { path: file.path, workflow };
			}
			let text: string;
			try {
				const content = await gh<GitHubContent>(
					creds,
					`${repoPath(a)}/contents/${file.path.split("/").map(encodeURIComponent).join("/")}`,
					{ query },
				);
				text = decodeBase64(content.content ?? "");
			} catch {
				return { path: file.path, unreadable: true as const };
			}
			const workflow = parseWorkflow(text);
			if (file.sha) {
				byBlob.set(file.sha, workflow);
			}
			return { path: file.path, workflow };
		}),
	);

	return {
		kind: "ok",
		dir: {
			parsed: results.flatMap((r) =>
				"workflow" in r && r.workflow ? [{ path: r.path, workflow: r.workflow }] : [],
			),
			unreadable: results.filter((r) => "unreadable" in r).map((r) => r.path),
			invalid: results
				.filter((r) => "workflow" in r && r.workflow === undefined)
				.map((r) => r.path),
			unchecked: files.slice(MAX_WORKFLOW_FILES).map((file) => file.path),
			byBlob,
		},
	};
}

/**
 * Lists the workflows that a release change will start: the `release` and tag
 * workflows at `ref`, and the `workflow_run` workflows on the default branch
 * that follow them. Best-effort: a failure to read is reported, not thrown,
 * because it must never stop a release from being previewed.
 */
export async function releaseWorkflows(
	creds: TokenSource,
	a: Repo,
	ref: string,
	options: { actions: ReleaseAction[]; createsTag: boolean },
): Promise<WorkflowReport> {
	const { actions, createsTag } = options;
	const atRef = await readWorkflowDir(creds, a, ref);
	if (atRef.kind === "missing") {
		return {
			triggered_by_release: [],
			release_actions: actions,
			files_checked: 0,
			note: "No workflows at this ref.",
		};
	}
	if (atRef.kind === "error") {
		return {
			triggered_by_release: [],
			release_actions: actions,
			files_checked: 0,
			note: `Could not read .github/workflows, so the workflows this starts are unknown: ${atRef.message}`,
		};
	}

	const { parsed, unreadable, invalid, unchecked } = atRef.dir;
	const select = (test: (workflow: ParsedWorkflow) => boolean) =>
		parsed.filter((r) => test(r.workflow));
	const refs = (list: Parsed[]) => list.map((r) => ({ path: r.path, name: r.workflow.name }));

	const byRelease = select((w) => triggersOnRelease(w, actions));
	const byTag = createsTag ? select(triggersOnTagCreation) : [];
	const started = [...byRelease, ...byTag];

	const unanalysed = [...unreadable, ...invalid];
	// Workflows at the ref whose name and triggers are unknown: any of them may
	// start, and a workflow_run consumer may be waiting for it.
	const unknownAtRef = unanalysed.length > 0 || unchecked.length > 0;

	const notes: string[] = [];
	if (unreadable.length) {
		notes.push(`Could not read: ${unreadable.join(", ")}.`);
	}
	if (invalid.length) {
		notes.push(
			`Could not be analysed, so they may still run: ${invalid.join(", ")}. GitHub's ` +
				`workflow parser can accept files this one rejects.`,
		);
	}
	if (unchecked.length) {
		notes.push(`Only the first ${MAX_WORKFLOW_FILES} workflow files were checked.`);
	}

	// GitHub runs `workflow_run` workflows from the default branch, so that is
	// where their consumers are read. Nothing can follow if nothing starts.
	let byWorkflowRun: Parsed[] = [];
	let possibly: Parsed[] = [];
	let defaultUnanalysed: string[] = [];
	let defaultUnchecked: string[] = [];
	let defaultUnreadable = false;
	if (started.length || unknownAtRef) {
		const onDefault = await readWorkflowDir(creds, a, undefined, atRef.dir.byBlob);
		if (onDefault.kind === "error") {
			defaultUnreadable = true;
			notes.push(
				"Could not read .github/workflows on the default branch, where GitHub reads " +
					"`workflow_run` workflows from, so any that follow are unknown: " +
					`${onDefault.message}`,
			);
		} else if (onDefault.kind === "ok") {
			const all = onDefault.dir.parsed;
			byWorkflowRun = workflowRunChain(all, started);

			if (unknownAtRef) {
				// A consumer waiting for a name no starting workflow at the ref has
				// may be waiting for one of the unanalysed files, even when a parsed
				// workflow that does not start shares that name.
				const known = new Set(started.map(workflowLabel));
				const listed = new Set(byWorkflowRun.map((w) => w.path));
				const unresolved = all.filter(
					(w) =>
						!listed.has(w.path) &&
						(workflowRunSources(w.workflow) ?? []).some((name) => !known.has(name)),
				);
				possibly = [...unresolved, ...workflowRunChain(all, unresolved)].filter(
					(w, i, list) =>
						!listed.has(w.path) && list.findIndex((x) => x.path === w.path) === i,
				);
			}

			defaultUnanalysed = [...onDefault.dir.unreadable, ...onDefault.dir.invalid];
			defaultUnchecked = onDefault.dir.unchecked;
			if (defaultUnanalysed.length) {
				notes.push(
					`Could not analyse these default-branch workflows, so they may run on ` +
						`\`workflow_run\`: ${defaultUnanalysed.join(", ")}.`,
				);
			}
			if (defaultUnchecked.length) {
				notes.push(
					`Only the first ${MAX_WORKFLOW_FILES} workflow files on the default branch ` +
						`were checked.`,
				);
			}
			if (possibly.length) {
				notes.push(
					"possibly_triggered_by_workflow_run lists default-branch workflows waiting " +
						"for a workflow that could not be identified here; they may run.",
				);
			}
			if (byWorkflowRun.length || possibly.length) {
				notes.push(
					"`workflow_run` workflows were read from the default branch's current head, " +
						"which is where GitHub runs them from.",
				);
			}
		}
	}

	return {
		triggered_by_release: refs(byRelease),
		triggered_by_tag_creation: createsTag ? refs(byTag) : undefined,
		triggered_by_workflow_run: byWorkflowRun.length ? refs(byWorkflowRun) : undefined,
		possibly_triggered_by_workflow_run: possibly.length ? refs(possibly) : undefined,
		unanalysed: unanalysed.length ? unanalysed : undefined,
		unanalysed_on_default_branch: defaultUnanalysed.length ? defaultUnanalysed : undefined,
		unchecked_files_on_default_branch: defaultUnchecked.length ? defaultUnchecked : undefined,
		default_branch_unreadable: defaultUnreadable ? true : undefined,
		release_actions: actions,
		files_checked: parsed.length + invalid.length,
		unchecked_files: unchecked.length ? unchecked : undefined,
		note: notes.length ? notes.join(" ") : undefined,
	};
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The Contents API returns file bodies as base64 wrapped at 60 columns. */
function decodeBase64(encoded: string): string {
	const binary = atob(encoded.replace(/\s/g, ""));
	return new TextDecoder().decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
}
