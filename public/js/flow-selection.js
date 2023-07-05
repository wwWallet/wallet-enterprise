
// const params = new Proxy(new URLSearchParams(window.location.search), {
//   get: (searchParams, prop) => searchParams.get(prop),
// });
// // Get the value of "some_key" in eg "https://example.com/?some_key=some_value"
// let mode = params.mode; // "some_value"




// const sameDeviceDivElement = document.getElementById('same-device');
// if (sameDeviceDivElement != null) {
// 	sameDeviceDivElement.addEventListener('click', function (event) {
// 		console.log('clicked same device')
// 		// submit the form
// 		document.getElementById('flowSelectionForm').requestSubmit();
// 	});
// }



// if (document.getElementById('browser-only') != null)
// 	document.getElementById('browser-only').onclick = function (event) {
// 		window.location.href = '/view/flow-selection/browser-only';
// 	}

// device detection
// if is mobile then hide cross device flow
if( /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) ) {
 // some code..
	document.getElementById('cross-device').style.display = 'none';
}
