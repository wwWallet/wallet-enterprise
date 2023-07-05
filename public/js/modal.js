// Get the modal
var modal = document.getElementById("warning-modal");

// Get the <span> element that closes the modal
var span = document.getElementsByClassName("close")[0];

// When the user clicks on <span> (x), close the modal
if(span !== undefined) {
  span.onclick = function() {
    modal.style.display = "none";
  }
}
// When the user clicks anywhere outside of the modal, close it
window.onclick = function(event) {
  if (event.target == modal) {
    modal.style.display = "none";
  }
}

openModal = () => {
    modal.style.display = "block";
}

openModalWithId = (id) => {
  modal = document.getElementById("warning-modal-"+id);
  openModal();
}

closeModal = () => {
    modal.style.display = "none";
}