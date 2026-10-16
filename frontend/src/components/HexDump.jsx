/**
 * HexDump.jsx
 * Classic offset / hex / ASCII dump of real bytes.
 */

export default function HexDump({ bytes, rows = 8, width = 8, className = '' }) {
  if (!bytes?.length) {
    return <div className="text-outline text-[11px] font-mono">No bytes captured yet.</div>;
  }
  const lines = [];
  for (let off = 0; off < Math.min(bytes.length, rows * width); off += width) {
    const chunk = Array.from(bytes.slice(off, off + width));
    lines.push({
      off: off.toString(16).padStart(4, '0'),
      hex: chunk.map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(width * 3 - 1, ' '),
      asc: chunk.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join(''),
    });
  }
  const more = bytes.length - rows * width;

  return (
    <div className={`font-mono text-[11px] leading-relaxed ${className}`}>
      {lines.map(l => (
        <div key={l.off} className="flex gap-3 whitespace-pre">
          <span className="text-outline">{l.off}</span>
          <span className="text-primary">{l.hex}</span>
          <span className="text-on-surface-variant">{l.asc}</span>
        </div>
      ))}
      {more > 0 && <div className="text-outline">… {more} more bytes</div>}
    </div>
  );
}
