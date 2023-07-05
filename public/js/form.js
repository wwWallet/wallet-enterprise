function errorFeedback(id, timeout=3000, invalid="invalid", classes="") {
	document.getElementById(id).className = `${classes} form-control invalid`;
	document.getElementById(`${invalid}-${id}`).className = "error-feedback visible";

	setTimeout(() => {
		document.getElementById(id).className = `${classes} form-control`;
		document.getElementById(`${invalid}-${id}`).className = "error-feedback";
	}, timeout);
}