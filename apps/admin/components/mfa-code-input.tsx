interface MfaCodeInputProps {
  id: string;
  label: string;
  autoFocus?: boolean;
}

/** Uncontrolled: the enclosing form reads its value via FormData on submit. */
export function MfaCodeInput({ id, label, autoFocus }: MfaCodeInputProps) {
  return (
    <div className="field">
      <label htmlFor={id} className="field__label">
        {label}
      </label>
      <input
        id={id}
        name={id}
        type="text"
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="[0-9]*"
        maxLength={6}

        autoFocus={autoFocus}
        required
      />
    </div>
  );
}
