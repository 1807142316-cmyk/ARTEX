"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { http } from "@/lib/api";

interface SkillRunEvidence {
  id: number;
  client_run_id: string;
  skill: string;
  package_version: string;
  script_sha256: string;
  instructions_sha256: string;
  task_id?: number;
  input_label: string;
  input_sha256: string;
  input_kind: string;
  input_bytes: number;
  started_at: string;
  finished_at: string;
  outcome: string;
  exit_code: number;
  truncated: boolean;
  attestation: "operator_reported";
  received_at: string;
  stdout?: string;
  stderr?: string;
}

export function SkillRunEvidencePanel({ skill }: { skill: string }) {
  const [items, setItems] = useState<SkillRunEvidence[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [detail, setDetail] = useState<SkillRunEvidence | null>(null);
  const [error, setError] = useState("");
  const generation = useRef(0);
  const detailGeneration = useRef(0);
  const load = useCallback(async () => {
    const request = ++generation.current;
    try {
      const data = await http<{ items: SkillRunEvidence[]; total: number }>(
        `/skill-runs?skill=${encodeURIComponent(skill)}&page=${page}&limit=10`,
      );
      if (request !== generation.current) return;
      setItems(data.items);
      setTotal(data.total);
      setError("");
    } catch (err) {
      if (request === generation.current) setError(err instanceof Error ? err.message : String(err));
    }
  }, [skill, page]);
  useEffect(() => {
    void load();
    return () => {
      generation.current++;
      detailGeneration.current++;
    };
  }, [load]);
  const open = async (id: number) => {
    const request = ++detailGeneration.current;
    try {
      const data = await http<SkillRunEvidence>(`/skill-runs/${id}`);
      if (request === detailGeneration.current) setDetail(data);
    } catch (err) {
      if (request === detailGeneration.current) setError(err instanceof Error ? err.message : String(err));
    }
  };
  return (
    <section className="space-y-3 rounded-md border p-3">
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-medium text-sm">离线工作流执行证据</h3>
        <Button variant="outline" size="sm" onClick={() => void load()}>
          刷新
        </Button>
      </div>
      <p className="text-muted-foreground text-xs">
        固定脚本运行器上报的结果，与 Skill 正文加载计数分开。来源标记为操作方上报，不表示平台独立验证。
      </p>
      {error && <p className="text-destructive text-xs">{error}</p>}
      {items.length === 0 ? (
        <p className="text-muted-foreground text-xs">
          尚无执行报告。离线工作流执行并上报后，可在这里查看输入摘要、退出状态和结果。
        </p>
      ) : (
        <div className="space-y-2">
          {items.map((item) => (
            <div key={item.id} className="flex flex-wrap items-center gap-2 border-b pb-2 text-xs last:border-0">
              <span>{new Date(item.started_at).toLocaleString()}</span>
              <Badge variant="outline">{item.outcome}</Badge>
              <span>exit {item.exit_code}</span>
              <span className="text-muted-foreground">{item.input_label}</span>
              <Button size="sm" variant="ghost" onClick={() => void open(item.id)}>
                查看输入摘要与结果
              </Button>
            </div>
          ))}
        </div>
      )}
      {total > 10 && (
        <div className="flex items-center gap-2 text-xs">
          <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage(page - 1)}>
            上一页
          </Button>
          <span>
            {page} / {Math.ceil(total / 10)}
          </span>
          <Button size="sm" variant="outline" disabled={page * 10 >= total} onClick={() => setPage(page + 1)}>
            下一页
          </Button>
        </div>
      )}
      {detail && (
        <div className="space-y-2 rounded-md bg-muted/40 p-3 text-xs">
          <div className="flex justify-between">
            <strong>报告 #{detail.id} · 操作方上报</strong>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                detailGeneration.current++;
                setDetail(null);
              }}
            >
              关闭
            </Button>
          </div>
          <p>
            版本 {detail.package_version} · {detail.outcome} · exit {detail.exit_code}
            {detail.truncated ? " · 输出已截断" : ""}
          </p>
          <p>
            {detail.input_kind} · {detail.input_label} · {detail.input_bytes} bytes
            {detail.task_id ? ` · 任务 #${detail.task_id}` : " · 未关联任务"}
          </p>
          <p className="break-all font-mono">输入 SHA-256: {detail.input_sha256}</p>
          <p className="break-all font-mono">脚本 SHA-256: {detail.script_sha256}</p>
          <p>
            {detail.started_at} → {detail.finished_at}
          </p>
          <details>
            <summary className="cursor-pointer">stdout</summary>
            <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all">{detail.stdout || "（空）"}</pre>
          </details>
          <details>
            <summary className="cursor-pointer">stderr</summary>
            <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all">{detail.stderr || "（空）"}</pre>
          </details>
        </div>
      )}
    </section>
  );
}
