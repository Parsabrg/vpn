export interface FilterField {
  name: string;
  label: string;
  type: "text" | "select";
  options?: { value: string; label: string }[];
}

interface FilterBarProps {
  fields: FilterField[];
  values: Record<string, string | undefined>;
}

/** A plain GET-navigating form: filtering works without any client JS. */
export function FilterBar({ fields, values }: FilterBarProps) {
  return (
    <form className="filter-bar" role="search">
      {fields.map((field) => (
        <div className="field" key={field.name}>
          <label htmlFor={`filter-${field.name}`} className="field__label">
            {field.label}
          </label>
          {field.type === "select" ? (
            <select
              id={`filter-${field.name}`}
              name={field.name}
              defaultValue={values[field.name] ?? ""}
            >
              <option value="">Any</option>
              {field.options?.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          ) : (
            <input
              id={`filter-${field.name}`}
              name={field.name}
              type="text"
              defaultValue={values[field.name] ?? ""}
            />
          )}
        </div>
      ))}
      <button type="submit" className="button button--secondary">
        Filter
      </button>
    </form>
  );
}
