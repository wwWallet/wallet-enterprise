var queryString = window.location.search;
var urlParams = new URLSearchParams(queryString);

if(urlParams.get('update')) {
	popupAlert('update-success');
}

toggleDetails = () => {

	const edit = document.getElementsByClassName('edit-details');
	const showcase = document.getElementsByClassName('show-details');

	for (const field of edit) {
		field.classList.toggle('hidden');
	}

	for (const cell of showcase) {
		cell.classList.toggle('hidden');
	}

}