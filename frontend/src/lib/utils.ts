import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

export function formatDate(iso: string | undefined | null) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(undefined, {
      year:   "numeric",
      month:  "short",
      day:    "2-digit",
      hour:   "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}
