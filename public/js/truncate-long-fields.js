document.addEventListener('DOMContentLoaded', () => {
	const MAX_LENGTH = 120;

	const truncateValue = (value) => {
		if (typeof value === 'string' && value.length > MAX_LENGTH) {
			return value.slice(0, MAX_LENGTH) + '...';
		}
		return value;
	};

	document.querySelectorAll('.claim-value').forEach(td => {
		try {
			const raw = td.getAttribute('data-raw-value');
			if (!raw) return;
			const truncated = truncateValue(raw);
			td.textContent = truncated;
		} catch (e) {
			console.error('Truncation error:', e);
		}
	});
});
