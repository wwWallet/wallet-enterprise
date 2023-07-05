const copyToClipboard = (data) => {
	navigator.clipboard.writeText(data).then(function() {
		console.log('Successfully copied data to clipboard');
		popupAlert('copy-success');
	}, function(err) {
		console.error('Could not copy text to clipboard: ', err);
		popupAlert('copy-error');
	});
}