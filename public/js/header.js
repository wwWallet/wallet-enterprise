
document.addEventListener("DOMContentLoaded", function() {
	const ribbon = document.querySelector('.ribbon');
	const menuArea = document.querySelector('.menu-area');

	// Check if ribbon is displayed as block
	if (window.getComputedStyle(ribbon).display === "block") {
			// Set menu-area margin-right to 20% if ribbon is visible
			menuArea.style.marginRight = "30%";
	} else {
			// Otherwise, keep it at 10%
			menuArea.style.marginRight = "10%";
	}
});

// change language cookie (eg lang=en)
// refresh window


if (document.getElementById('lang-el'))
	document.getElementById('lang-el').onclick = function (event) {
		document.cookie = 'lang=el; path=/'
		window.location.reload();
	}


if (document.getElementById('lang-en'))
	document.getElementById('lang-en').onclick = function (event) {
		document.cookie = 'lang=en; path=/';
		window.location.reload();
	}
