

for (const prov of document.getElementsByClassName('item')) {
	prov.addEventListener('click', function (event) {
		console.log('value = ' ,this.id)
		const id = this.id.split('-')[1];
		var hidden = document.getElementById("selected_provider_id");
		hidden.value = id;
		document.selectProvider.submit();
	});
}
