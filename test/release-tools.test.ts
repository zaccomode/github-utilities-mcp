import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppEnv } from "../src/env";
import type { TokenSource } from "../src/github/client";
import type { Register, ToolContext } from "../src/tools/common";
import { registerReleaseTools } from "../src/tools/releases";
import { aliasBomb } from "./fixtures";

/**
 * The release tools' handlers against a fake GitHub API: every request goes
 * through `fetch`, which is stubbed here to answer from `state` and record
 * what was sent.
 */

const source: TokenSource = {
	kind: "app",
	label: "a test identity",
	async token() {
		return "test-token";
	},
	async renew() {
		return null;
	},
};

const ctx: ToolContext = {
	env: env as unknown as AppEnv,
	creds: { app: source, user: source, as: () => source },
	tenant: {
		installationId: 1,
		accountLogin: "acme",
		accountType: "Organization",
		appSlug: "test-app",
		botLogin: "test-app[bot]",
		login: "octocat",
		userId: 1,
	},
	waitUntil: () => undefined,
};

type Handler = (args: Record<string, unknown>) => Promise<any>;
const handlers = new Map<string, Handler>();
const register: Register = (name, _config, handler) => handlers.set(name, handler);
registerReleaseTools(register, ctx);

function tool(name: string): Handler {
	const handler = handlers.get(name);
	if (!handler) {
		throw new Error(`No tool ${name}`);
	}
	return (args) =>
		handler({ owner: "acme", repo: "app", act_as: "app", confirm: false, ...args });
}

const SHA = "a".repeat(40);
const DEPLOY = "name: Deploy\non:\n  release:\n    types: [released]\n";
const TAG_PUSH = "name: Tags\non:\n  push:\n    tags: ['v*']\n";

interface State {
	release: Record<string, unknown>;
	tags: Set<string>;
	workflows: Record<string, string>;
	/** The default branch's workflows; the tag's are used when unset. */
	defaultWorkflows?: Record<string, string>;
	/** Makes listing the default branch's workflows fail. */
	defaultBranchError?: boolean;
	/** Every workflow file fetched, as "<ref or default>:<name>". */
	fileReads: string[];
	patches: unknown[];
}
let state: State;

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function fakeGitHub(input: RequestInfo | URL, init?: RequestInit): Response {
	const url = new URL(input instanceof Request ? input.url : String(input));
	const path = url.pathname.replace("/repos/acme/app", "");
	const method = init?.method ?? "GET";

	if (path === "/releases/1" && method === "GET") {
		return json(state.release);
	}
	if (path === "/releases/1" && method === "PATCH") {
		const patch = JSON.parse(String(init?.body));
		state.patches.push(patch);
		return json({ ...state.release, ...patch });
	}
	const ref = path.match(/^\/git\/ref\/tags\/(.+)$/);
	if (ref) {
		return state.tags.has(decodeURIComponent(ref[1]))
			? json({ ref: `refs/tags/${ref[1]}` })
			: json({ message: "Not Found" }, 404);
	}
	if (path.startsWith("/commits/")) {
		return json({ sha: SHA });
	}
	// No `ref` means the default branch, as in the real Contents API.
	const at = url.searchParams.get("ref");
	const workflows = at === null ? (state.defaultWorkflows ?? state.workflows) : state.workflows;
	if (path === "/contents/.github/workflows") {
		if (at === null && state.defaultBranchError) {
			return json({ message: "Server Error" }, 502);
		}
		return json(
			Object.entries(workflows).map(([name, text]) => ({
				type: "file",
				name,
				path: `.github/workflows/${name}`,
				// Stands in for the blob SHA: equal exactly when the contents are.
				sha: btoa(text),
			})),
		);
	}
	const file = path.match(/^\/contents\/\.github\/workflows\/(.+)$/);
	if (file && workflows[file[1]] !== undefined) {
		state.fileReads.push(`${at ?? "default"}:${file[1]}`);
		return json({ type: "file", content: btoa(workflows[file[1]]) });
	}
	return json({ message: `Unexpected ${method} ${path}` }, 500);
}

beforeEach(() => {
	state = {
		release: {
			id: 1,
			tag_name: "v1.0.0",
			target_commitish: "main",
			name: "v1.0.0",
			body: "notes",
			draft: true,
			prerelease: false,
			author: null,
			created_at: "2026-11-19T00:00:00Z",
			updated_at: "2026-11-19T00:00:00Z",
			published_at: null,
			html_url: "https://github.com/acme/app/releases/1",
		},
		tags: new Set(),
		workflows: { "deploy.yml": DEPLOY, "tags.yml": TAG_PUSH },
		fileReads: [],
		patches: [],
	};
	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) =>
		fakeGitHub(input as RequestInfo, init),
	);
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("publish_release", () => {
	const publish = tool("publish_release");

	it("refuses a draft with a placeholder tag", async () => {
		state.release.tag_name = "untagged-24962f94d18b366c8863";
		await expect(publish({ release_id: 1 })).rejects.toThrow(/placeholder/);
		expect(state.patches).toEqual([]);
	});

	it("previews a new tag, lists its workflows and publishes pinned to the sha", async () => {
		const preview = await publish({ release_id: 1 });
		expect(preview.published).toBe(false);
		expect(preview.tag).toMatch(/Creates tag v1.0.0/);
		expect(preview.workflows.triggered_by_release.map((w: any) => w.path)).toEqual([
			".github/workflows/deploy.yml",
		]);
		expect(preview.workflows.triggered_by_tag_creation.map((w: any) => w.path)).toEqual([
			".github/workflows/tags.yml",
		]);
		expect(state.patches).toEqual([]);

		const done = await publish({
			release_id: 1,
			confirm: true,
			confirm_token: preview.confirm_token,
		});
		expect(done.published).toBe(true);
		expect(state.patches).toEqual([{ draft: false, target_commitish: SHA }]);
	});

	it("does not pin target_commitish when the tag already exists", async () => {
		state.tags.add("v1.0.0");
		const preview = await publish({ release_id: 1 });
		expect(preview.tag).toMatch(/existing tag/);
		expect(preview.workflows.triggered_by_tag_creation).toBeUndefined();

		await publish({ release_id: 1, confirm: true, confirm_token: preview.confirm_token });
		expect(state.patches).toEqual([{ draft: false }]);
	});

	it("does not list a types: [released] workflow for a prerelease", async () => {
		state.release.prerelease = true;
		const preview = await publish({ release_id: 1 });
		expect(preview.workflows.triggered_by_release).toEqual([]);
	});

	it("marks the release and workflow text as untrusted", async () => {
		const preview = await publish({ release_id: 1 });
		expect(preview.untrusted_fields).toEqual(
			expect.arrayContaining([
				"release.name",
				"workflows.triggered_by_release[].name",
				"workflows.triggered_by_tag_creation[].name",
			]),
		);
		const done = await publish({
			release_id: 1,
			confirm: true,
			confirm_token: preview.confirm_token,
		});
		expect(done.untrusted_fields).toEqual(preview.untrusted_fields);
	});

	it("lists an unparseable workflow as unanalysed instead of failing", async () => {
		state.workflows["bomb.yml"] = aliasBomb();
		state.workflows["broken.yml"] = "on: [release\n";
		const preview = await publish({ release_id: 1 });
		expect(preview.workflows.unanalysed).toEqual([
			".github/workflows/bomb.yml",
			".github/workflows/broken.yml",
		]);
		expect(preview.workflows.note).toMatch(/may still run/);
		expect(preview.workflows.triggered_by_release.map((w: any) => w.path)).toEqual([
			".github/workflows/deploy.yml",
		]);

		// A file that becomes unanalysable after the preview changes the token.
		delete state.workflows["broken.yml"];
		await expect(
			publish({ release_id: 1, confirm: true, confirm_token: preview.confirm_token }),
		).rejects.toThrow(/changed since the preview/);
	});

	it("lists workflow_run workflows chained after the release ones", async () => {
		state.workflows["after.yml"] =
			"name: After deploy\non:\n  workflow_run:\n    workflows: [Deploy]\n";
		const preview = await publish({ release_id: 1 });
		expect(preview.workflows.triggered_by_workflow_run).toEqual([
			{ path: ".github/workflows/after.yml", name: "After deploy" },
		]);
		expect(preview.workflows.note).toMatch(/default branch/);
	});

	it("reads workflow_run consumers from the default branch, not the tag", async () => {
		// The tag predates after.yml; GitHub still runs it, from the default branch.
		state.defaultWorkflows = {
			...state.workflows,
			"after.yml": "name: After deploy\non:\n  workflow_run:\n    workflows: [Deploy]\n",
		};
		const preview = await publish({ release_id: 1 });
		expect(preview.workflows.triggered_by_workflow_run).toEqual([
			{ path: ".github/workflows/after.yml", name: "After deploy" },
		]);
		expect(preview.workflows.note).toMatch(/default branch/);

		// Files unchanged between the tag and the default branch are fetched once.
		expect(state.fileReads.filter((r) => r.startsWith("default:"))).toEqual([
			"default:after.yml",
		]);

		// The consumer is bound into the token: dropping it changes the token.
		delete state.defaultWorkflows["after.yml"];
		await expect(
			publish({ release_id: 1, confirm: true, confirm_token: preview.confirm_token }),
		).rejects.toThrow(/changed since the preview/);
	});

	it("ignores workflow_run consumers that exist only at the tag", async () => {
		state.workflows["after.yml"] =
			"name: After deploy\non:\n  workflow_run:\n    workflows: [Deploy]\n";
		state.defaultWorkflows = { "deploy.yml": DEPLOY };
		const preview = await publish({ release_id: 1 });
		expect(preview.workflows.triggered_by_workflow_run).toBeUndefined();
	});

	it("says so, and binds it into the token, when the default branch cannot be read", async () => {
		state.defaultBranchError = true;
		const preview = await publish({ release_id: 1 });
		expect(preview.workflows.default_branch_unreadable).toBe(true);
		expect(preview.workflows.note).toMatch(/Could not read .*default branch/);

		state.defaultBranchError = false;
		await expect(
			publish({ release_id: 1, confirm: true, confirm_token: preview.confirm_token }),
		).rejects.toThrow(/changed since the preview/);
	});

	it("lists consumers of an unanalysed workflow as possibly triggered", async () => {
		state.workflows["release.yml"] = "name: Release\non: [release\n";
		state.defaultWorkflows = {
			...state.workflows,
			"ship.yml": "name: Ship\non:\n  workflow_run:\n    workflows: [Release]\n",
			"after.yml": "name: After deploy\non:\n  workflow_run:\n    workflows: [Deploy]\n",
		};
		const preview = await publish({ release_id: 1 });
		expect(preview.workflows.unanalysed).toEqual([".github/workflows/release.yml"]);
		expect(preview.workflows.triggered_by_workflow_run).toEqual([
			{ path: ".github/workflows/after.yml", name: "After deploy" },
		]);
		expect(preview.workflows.possibly_triggered_by_workflow_run).toEqual([
			{ path: ".github/workflows/ship.yml", name: "Ship" },
		]);
		expect(preview.untrusted_fields).toEqual(
			expect.arrayContaining(["workflows.possibly_triggered_by_workflow_run[].name"]),
		);
	});

	it("refuses confirm without a token", async () => {
		await expect(publish({ release_id: 1, confirm: true })).rejects.toThrow(
			/needs the confirm_token/,
		);
		expect(state.patches).toEqual([]);
	});

	it("refuses a token that no longer matches", async () => {
		const preview = await publish({ release_id: 1 });
		state.release.body = "changed";
		await expect(
			publish({ release_id: 1, confirm: true, confirm_token: preview.confirm_token }),
		).rejects.toThrow(/changed since the preview/);
		expect(state.patches).toEqual([]);
	});

	it("refuses the token when the tag is deleted after the preview", async () => {
		state.tags.add("v1.0.0");
		const preview = await publish({ release_id: 1 });
		state.tags.delete("v1.0.0");
		await expect(
			publish({ release_id: 1, confirm: true, confirm_token: preview.confirm_token }),
		).rejects.toThrow(/changed since the preview/);
		expect(state.patches).toEqual([]);
	});
});

describe("update_release", () => {
	const update = tool("update_release");

	it("refuses to promote a published prerelease", async () => {
		Object.assign(state.release, { draft: false, prerelease: true });
		await expect(
			update({ release_id: 1, prerelease: false, allow_published: true }),
		).rejects.toThrow(/promote_release/);
		expect(state.patches).toEqual([]);
	});

	it("still edits a published prerelease's notes", async () => {
		Object.assign(state.release, { draft: false, prerelease: true });
		await update({ release_id: 1, body: "new notes", allow_published: true });
		expect(state.patches).toHaveLength(1);
	});
});

describe("promote_release", () => {
	const promote = tool("promote_release");

	beforeEach(() => {
		Object.assign(state.release, { draft: false, prerelease: true });
		state.tags.add("v1.0.0");
	});

	it("previews the released workflows, then promotes with the token", async () => {
		const preview = await promote({ release_id: 1 });
		expect(preview.promoted).toBe(false);
		expect(preview.workflows.release_actions).toEqual(["edited", "released"]);
		expect(preview.workflows.triggered_by_release.map((w: any) => w.name)).toEqual(["Deploy"]);
		expect(state.patches).toEqual([]);

		const done = await promote({
			release_id: 1,
			confirm: true,
			confirm_token: preview.confirm_token,
		});
		expect(done.promoted).toBe(true);
		expect(state.patches).toEqual([{ prerelease: false }]);
	});

	it("marks the release and workflow text as untrusted", async () => {
		const preview = await promote({ release_id: 1 });
		expect(preview.untrusted_fields).toEqual(
			expect.arrayContaining(["release.name", "workflows.triggered_by_release[].name"]),
		);
		const done = await promote({
			release_id: 1,
			confirm: true,
			confirm_token: preview.confirm_token,
		});
		expect(done.untrusted_fields).toEqual(preview.untrusted_fields);
	});

	it("refuses a token from a publish preview", async () => {
		await expect(
			promote({ release_id: 1, confirm: true, confirm_token: "0000000000000000" }),
		).rejects.toThrow(/changed since the preview/);
	});

	it("refuses a full release and a draft", async () => {
		state.release.prerelease = false;
		await expect(promote({ release_id: 1 })).rejects.toThrow(/already a full release/);
		Object.assign(state.release, { draft: true, prerelease: true });
		await expect(promote({ release_id: 1 })).rejects.toThrow(/is a draft/);
	});
});
