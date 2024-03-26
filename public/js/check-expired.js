function updateLayoutForExpiredCredentials(credentialPayloads) {
	const currentDate = new Date();
	credentialPayloads.forEach((credential, index) => {
		const expirationDate = new Date(credential.expirationDate);
		if (expirationDate < currentDate) {
			const credentialBox = document.querySelectorAll('.credential-box')[index];
			credentialBox.classList.add('expired-credential');
			const expiredLabel = document.createElement('div');
			expiredLabel.className = 'expired-label';
			expiredLabel.textContent = 'Expired';
			credentialBox.appendChild(expiredLabel);
		}
	});
}