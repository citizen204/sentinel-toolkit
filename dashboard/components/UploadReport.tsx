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

function readReport(file: File): Promise<Report> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error(`could not read ${file.name}`));
    reader.onload = () => {
      try {
        const data = JSON.parse(String(reader.result));
        if (!isReport(data)) {
          throw new Error(`${file.name} is not a Sentinel report`);
        }
        resolve(data);
      } catch (e) {
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    };
    reader.readAsText(file);
  });
}

export default function UploadReport({
  onLoad,
}: {
  onLoad: (reports: Report[]) => void;
}) {
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleFiles(files: FileList) {
    try {
      const reports = await Promise.all([...files].map(readReport));
      setError(null);
      onLoad(reports);
    } catch (e) {
      setError(`Could not load report: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  function onInput(e: ChangeEvent<HTMLInputElement>) {
    if (e.target.files?.length) handleFiles(e.target.files);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files?.length) handleFiles(e.dataTransfer.files);
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
        <span className="underline">Choose report.json file(s)</span>
        <input
          type="file"
          multiple
          accept="application/json,.json"
          onChange={onInput}
          className="hidden"
        />
      </label>
      <span className="text-slate-500">
        {" "}
        or drag &amp; drop them here — add several runs to see trend and diff.
      </span>
      {error && <p className="mt-2 text-red-600">{error}</p>}
    </div>
  );
}
