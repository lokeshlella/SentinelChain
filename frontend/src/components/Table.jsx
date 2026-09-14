// Generic table. columns: [{ key, label, render?(row), className? }]. rows: array of objects.
export default function Table({ columns, rows, rowKey, empty = 'Nothing to show.', compact = false }) {
  const list = Array.isArray(rows) ? rows : []
  return (
    <div className="table-wrap">
      <table className={`table${compact ? ' compact' : ''}`}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={c.className}>{c.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {list.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="muted">{empty}</td>
            </tr>
          )}
          {list.map((row, i) => (
            <tr key={rowKey ? rowKey(row, i) : i}>
              {columns.map((c) => {
                let value
                try {
                  value = c.render ? c.render(row, i) : row?.[c.key]
                } catch {
                  value = '—'
                }
                if (value === null || value === undefined || value === '') value = <span className="muted">—</span>
                return <td key={c.key} className={c.className}>{value}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
