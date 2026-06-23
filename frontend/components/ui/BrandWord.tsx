export function BrandWord({ className = '' }: { className?: string }) {
  return (
    <span className={`brand-word ${className}`.trim()}>
      A<span className="dash">-</span>DAP<span className="dash">-</span>T
    </span>
  );
}
