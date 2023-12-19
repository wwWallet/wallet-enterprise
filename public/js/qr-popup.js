const qrDialog = document.getElementById('qrDialog');
const qrImage = document.getElementById('qrImage');
const qrURL = document.getElementById('qrURL');
const closeDialogBtn = document.getElementById('closeDialogBtn');

function openDialog(qrCodeURL, url) {
	qrImage.src = qrCodeURL;
	qrURLwwwallet.onclick = (e) => {
		url = url.replace('openid-credential-offer://', 'https://demo.wwwallet.org/cb');
		console.log(url);
		e.preventDefault();
		window.location.href = url;
	}
	qrURLnative.onclick = (e) => {
		e.preventDefault();
		window.location.href = url;
	}
	qrDialog.showModal();
}

function closeDialog() {
	qrDialog.close();
}

// Handle "Scan QR" button click
const scanQRButtons = document.querySelectorAll('.credential .Btn.Small.ScanQRBtn');
scanQRButtons.forEach(button => {
	button.addEventListener('click', () => {
		const credentialOfferQR = button.dataset.credentialOfferQR;
		openDialog(credentialOfferQR);
	});
});

closeDialogBtn.addEventListener('click', closeDialog);