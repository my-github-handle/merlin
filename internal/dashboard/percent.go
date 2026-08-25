package dashboard

// Every headline figure on the dashboard is a part-of-whole percentage, and every one of
// their denominators can legitimately be zero: a window with no pushes, a day with no
// rejections, a pod whose first scan has not finished. Before this file each site did the
// division itself with its own zero guard, which is a guard that only has to be forgotten
// once to put "NaN%" in front of an operator during the outage they opened the page for.
//
// So there is exactly one division. Callers pass a numerator and a denominator; nobody
// multiplies by 100 anywhere else.

// pct returns part/whole as a percentage, and 0 — never NaN or ±Inf — when there is
// nothing to divide by.
//
// whole <= 0 rather than == 0: these are counter reads, and a negative total means the
// gatherer handed back something impossible. Zero is the honest answer to both.
func pct(part, whole float64) float64 {
	if whole <= 0 {
		return 0
	}
	return part / whole * 100
}

// PassRate returns passed/total as a percentage (0 when total is 0). Exported because it
// is the one figure other packages and the JSON contract quote by name.
func PassRate(passed, total uint64) float64 {
	return pct(float64(passed), float64(total))
}
