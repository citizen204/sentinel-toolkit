"use client";

import { ChangeEvent, DragEvent, useState } from "react";
import { Report } from "@/lib/types";

function isReport(data: unknown): data is Report {
  return (
    !!data &&
    typeof data === "object" &&
    Array.isArray((data as Report).findings) &&
    typeof (data as Report).summary === "object"
  );
}

export default function UploadReport({
  onLoad,
}: {
  onLoad: (report: Report) => void;
}) {
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function handleFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = JSON.parse(String(reader.result));
        if (!isReport(data)) {
          throw new Error("not a Sentinel report (missing summary/findings)");
        }
        setError(null);
        onLoad(data);
      } catch (e) {
        setError(
          `Could not load report: ${e instanceof Error ? e.message : String(e)}`,
        );
      }
    };
    reader.readAsText(file);
  }

  function onInput(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  }

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
      className={`rounded-lg border-2 border-dashed p-4 text-sm transition ${
        dragging ? "border-slate-900 bg-slate-100" : "border-slate-300 bg-white"
      }`}
    >
      <label className="cursor-pointer font-medium text-slate-700">
        <span className="underline">Choose a report.json</span>
        <input
          type="file"
          accept="application/json,.json"
          onChange={onInput}
          className="hidden"
        />
      </label>
      <span className="text-slate-500"> or drag &amp; drop one here.</span>
      {error && <p className="mt-2 text-red-600">{error}</p>}
    </div>
  );
}
