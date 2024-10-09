export function formatDateDDMMYYYY(value: any): string {
	const stringValue = value ? String(value) : null;
	const date = stringValue ? new Date(stringValue) : new Date();
	const padZero = (num: number) => (num < 10 ? '0' + num : num);

	const day = padZero(date.getDate());
	const month = padZero(date.getMonth() + 1); // Months are 0-indexed
	const year = date.getFullYear();

	return `${day}/${month}/${year}`;
}
