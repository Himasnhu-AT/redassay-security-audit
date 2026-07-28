// Multi-select state for the findings list.
//
// Batch fixing is the reason the board exists - a reviewer approves eight
// findings at once and lets the agent work through them - so selection needs to
// survive filtering, support shift-range picking, and never hand the server an
// id that is no longer visible.

export class Selection {
  constructor(ids = []) {
    this.ids = new Set(ids);
    this.anchor = null;
  }

  get size() {
    return this.ids.size;
  }

  has(id) {
    return this.ids.has(id);
  }

  toArray() {
    return [...this.ids];
  }

  clear() {
    this.ids.clear();
    this.anchor = null;
    return this;
  }

  toggle(id) {
    if (this.ids.has(id)) this.ids.delete(id);
    else this.ids.add(id);
    this.anchor = id;
    return this;
  }

  set(id) {
    this.ids = new Set([id]);
    this.anchor = id;
    return this;
  }

  /** Shift-click: select everything between the anchor and `id` in `ordered`. */
  extendTo(id, ordered) {
    const list = ordered.map((item) => (typeof item === "string" ? item : item.id));
    const end = list.indexOf(id);
    if (end === -1) return this;
    const start = this.anchor === null ? end : list.indexOf(this.anchor);
    if (start === -1) {
      this.ids.add(id);
      this.anchor = id;
      return this;
    }
    const [from, to] = start <= end ? [start, end] : [end, start];
    for (let index = from; index <= to; index += 1) this.ids.add(list[index]);
    return this;
  }

  selectAll(ordered) {
    for (const item of ordered) this.ids.add(typeof item === "string" ? item : item.id);
    return this;
  }

  /** Drop ids that are no longer in the visible set. */
  prune(ordered) {
    const visible = new Set(ordered.map((item) => (typeof item === "string" ? item : item.id)));
    for (const id of [...this.ids]) {
      if (!visible.has(id)) this.ids.delete(id);
    }
    if (this.anchor !== null && !visible.has(this.anchor)) this.anchor = null;
    return this;
  }
}

/** Describe what a batch action is about to do, for the confirm line. */
export function describeBatch(findings, ids) {
  const chosen = (findings || []).filter((finding) => ids.includes(finding.id));
  if (!chosen.length) return "Nothing selected";
  const counts = {};
  for (const finding of chosen) counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  const parts = ["critical", "high", "medium", "low", "info"]
    .filter((name) => counts[name])
    .map((name) => `${counts[name]} ${name}`);
  const files = new Set(chosen.map((finding) => finding.location && finding.location.path));
  return `${chosen.length} finding${chosen.length === 1 ? "" : "s"} (${parts.join(", ")}) across ${files.size} file${files.size === 1 ? "" : "s"}`;
}
