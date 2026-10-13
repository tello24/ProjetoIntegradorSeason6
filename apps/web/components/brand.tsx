import Image from "next/image";

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div
      aria-label="WVM, Wolf Vulnerability Management, uma solução NeoGuardian"
      className={`brand${compact ? " brand--compact" : ""}`}
    >
      <span className="brand__mark">
        <Image
          alt=""
          height={42}
          priority
          src="/brand/neoguardian-wolf.png"
          width={42}
        />
      </span>
      {!compact && (
        <span className="brand__copy">
          <strong className="brand__text">WVM</strong>
          <small>Wolf Vulnerability Management</small>
        </span>
      )}
    </div>
  );
}
