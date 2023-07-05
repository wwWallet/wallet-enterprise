var filter = document.getElementById("form-container");

toggleFilters = () => {
	if (filter !== undefined) {
		if (filter.style.display === "none")
			filter.style.display = "block";
		else
			filter.style.display = "none";
	}
}