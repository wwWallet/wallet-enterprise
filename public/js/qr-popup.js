const qrDialog = document.getElementById('qrDialog');
const qrImage = document.getElementById('qrImage');
const qrURL = document.getElementById('qrURL');
const closeDialogBtn = document.getElementById('closeDialogBtn');

function openDialog(qrCodeURL, url) {
	qrImage.src = qrCodeURL;
	qrURL.onclick = (e) => {
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