// Definition list. items: [{ label, value }] — values may be React nodes; null/undefined render as "—".
export default function KeyValue({ items, columns = 2 }) {
  const list = (items || []).filter((it) => it && it.label)
  return (
    <dl className={`kv kv-${columns}`}>
      {list.map((it) => (
        <div className="kv-row" key={it.label}>
          <dt>{it.label}</dt>
          <dd>{it.value === null || it.value === undefined || it.value === '' ? <span className="muted">—</span> : it.value}</dd>
        </div>
      ))}
    </dl>
  )
}
