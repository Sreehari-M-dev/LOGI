// Hamburger Menu Functionality
function initHamburgerMenu() {
    const hamburger = document.getElementById('hamburger');
    const navMenu = document.getElementById('nav-menu');

    if (hamburger && navMenu) {
        hamburger.addEventListener('click', () => {
            hamburger.classList.toggle('active');
            navMenu.classList.toggle('active');
        });

        // Close menu when clicking on a link
        document.querySelectorAll('.nav-menu a').forEach(link => {
            link.addEventListener('click', () => {
                hamburger.classList.remove('active');
                navMenu.classList.remove('active');
            });
        });
    }
}

// Log Book Dynamic Row Functions
function addRow(event) {
    event.preventDefault();
    const table = document.getElementById('t1');
    if (!table) return;
    
    const rowCount = table.rows.length - 4; // Adjust for header rows and button row
    const newRow = table.insertRow(rowCount + 3);
    newRow.innerHTML = `
        <td>${rowCount + 1}</td>
        <td><input type="date" name="date${rowCount + 1}"></td>
        <td><input type="text" name="experiment${rowCount + 1}" id="exp${rowCount + 1}"></td>
        <td><input type="number" name="co${rowCount + 1}" min="0" max="9"></td>
        <td><input type="number" name="rubric${rowCount + 1}-1"></td>
        <td><input type="number" name="rubric${rowCount + 1}-2"></td>
        <td><input type="number" name="rubric${rowCount + 1}-3"></td>
        <td><input type="number" name="rubric${rowCount + 1}-4"></td>
        <td><input type="number" name="rubric${rowCount + 1}-5"></td>
        <td><input type="number" name="total${rowCount + 1}"></td>
        <td><input type="checkbox" name="student${rowCount + 1}"></td>
        <td><input type="checkbox" name="faculty${rowCount + 1}"></td>
    `;
}

function delRow(event) {
    event.preventDefault();
    const table = document.getElementById('t1');
    if (!table) return;
    
    const rowCount = table.rows.length - 4;
    if (rowCount > 1) {
        table.deleteRow(rowCount + 1);
    } else {
        alert("Cannot delete the last row");
    }
}

// Initialize all functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize hamburger menu on all pages
    initHamburgerMenu();
    
    // Add any other page-specific initializations here
    console.log('Digital Lab Portal scripts loaded successfully');
});