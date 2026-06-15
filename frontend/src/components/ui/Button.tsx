import { cn } from "@/lib/utils";
import { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size    = "sm" | "md" | "lg";

const variants: Record<Variant, string> = {
  primary:   "bg-accent hover:bg-accent/90 text-white border border-accent/60 shadow-soft",
  secondary: "bg-elev hover:bg-elev/70 text-text border border-border",
  ghost:     "bg-transparent hover:bg-elev/50 text-text border border-transparent",
  danger:    "bg-danger hover:bg-danger/90 text-white border border-danger/60",
};
const sizes: Record<Size, string> = {
  sm: "h-8 px-3 text-xs",
  md: "h-10 px-4 text-sm",
  lg: "h-11 px-5 text-sm",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  children: ReactNode;
}

export function Button({
  className, variant = "primary", size = "md", children, ...props
}: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60",
        variants[variant], sizes[size], className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}
