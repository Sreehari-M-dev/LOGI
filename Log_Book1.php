<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Book</title> 
    <link rel="stylesheet" href="styles.css">
</head>

<body>
    
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-logo">
                <a href="home.html">Digital Lab Portal</a>
            </div>
            <div class="hamburger" id="hamburger">
                <span></span>
                <span></span>
                <span></span>
            </div>
            <ul class="nav-menu" id="nav-menu">
                <li><a href="home.html">Home</a></li>
                <li><a href="Log_Book1.php" class="active">Log Book</a></li>
                <li><a href="Studyresources.html">Study Resources</a></li>
                <li><a href="About.html">About US</a></li>
            </ul>
        </div>
    </nav>
    <form action="logboo.php" method="post">
    <h1>Log Book</h1>
    <input type="submit" name="logout" value="logout" 
    style="float: top; margin-right: 20px; margin-top:0px; background-color: red; color: white; border: none; border-radius: 4px; cursor: pointer;">
    <table borde cellpadding="10px" class="ftab">
        <tr>
            <td><label for="">Name of Student</label></td>
            <td><input type="text" id="name" name="name"></td>
        </tr>
        <tr>
            <td><label for="rollno"  >Roll No</label></td>
            <td><input type="number" name="rollno"id="detail1" max="99" min="1"></td>
            <td><label for="rgno" >Register Number</label></td>
            <td><input type="number" name="rgno" maxlength="10" id="detail" min="0" max="3000000000"></td>
        </tr>
    </table><br><br>

    <table border="3" cellspacing="0" id="t1">
        <tr>
            <td rowspan="3"><b>Sl No</b></td>
            <td rowspan="3"><b>Date of Experiment</b></td>
            <td rowspan="3"><b>Name of Experiment</b></td>
            <td rowspan="3" id="c"><b>CO</b></td>
            <td colspan="6" style="width: 100px;">
                <b >Marks Awarded for lab Work</b>
            <td rowspan="2" colspan="2"><b>Signature</b></td>
        <tr>
            <td colspan="5"><b>Rubrics</b></td>
            <td rowspan="2"><b>TOTAL</b></td>
        </tr>
        <tr id="no">
            <td>1</td>
            <td>2</td>
            <td>3</td>
            <td>4</td>
            <td>5</td> 
            <td><b>Student</b></td>
            <td><b>Faculty</b></td>
        </tr>
        </td>
        </tr>
        <tr>
            <td>1<!--<input type="text" name="slno1">--></td>
            <td><input type="date" name="date1"></td>
            <td><input type="text" name="experiment1"  id="exp"></td>
            <td><input type="number"name="co1" min="0" max="9"  oninput="this.value=this.value.replace(/[^0-9]/g,'')"></td>
            <td><input type="number" name="rubric1-1" inputmode="numeric"></td>
            <td><input type="number" name="rubric1-2"></td>
            <td><input type="number" name="rubric1-3"></td>
            <td><input type="number" name="rubric1-4"></td>
            <td><input type="number" name="rubric1-5"></td>
            <td><input type="number" name="total1"></td>
            <td><input type="checkbox" name="student1"></td>
            <td><input type="checkbox" name="faculty1"></td>
        </tr>
        <tr>
            <td>2<!--<input type="text" name="slno2">--></td>
            <td><input type="date" name="date2"></td>
            <td><input type="text" name="experiment2" id="exp"></td>
            <td><input type="number" name="co2"></td>
            <td><input type="number" name="rubric2-1"></td>
            <td><input type="number" name="rubric2-2"></td>
            <td><input type="number" name="rubric2-3"></td>
            <td><input type="number" name="rubric2-4"></td>
            <td><input type="number" name="rubric2-5"></td>
            <td><input type="number" name="total2"></td>
            <td><input type="checkbox" name="student2"></td>
            <td><input type="checkbox" name="faculty2"></td>
        </tr>
        <tr>
            <td>3<!--<input type="text" name="slno3">--></td>
            <td><input type="date" name="date3"></td>
            <td><input type="text" name="experiment3" id="exp"></td>
            <td><input type="number" name="co3"></td>
            <td><input type="number" name="rubric3-1"></td>
            <td><input type="number" name="rubric3-2"></td>
            <td><input type="number" name="rubric3-3"></td>
            <td><input type="number" name="rubric3-4"></td>
            <td><input type="number" name="rubric3-5"></td>
            <td><input type="number" name="total3"></td>
            <td><input type="checkbox" name="student3"></td>
            <td><input type="checkbox" name="faculty3"></td>
        </tr>
        <tr>
            <td>4<!--<input type="text" name="slno4">--></td>
            <td><input type="date" name="date4"></td>
            <td><input type="text" name="experiment4" id="exp"></td>
            <td><input type="number" name="co4"></td>
            <td><input type="number" name="rubric4-1"></td>
            <td><input type="number" name="rubric4-2"></td>
            <td><input type="number" name="rubric4-3"></td>
            <td><input type="number" name="rubric4-4"></td>
            <td><input type="number" name="rubric4-5"></td>
            <td><input type="number" name="total4"></td>
            <td><input type="checkbox" name="student4"></td>
            <td><input type="checkbox" name="faculty4"></td>
        </tr>
        <tr>
            <td>5<!--<input type="text" name="slno5">--></td>
            <td><input type="date" name="date5"></td>
            <td><input type="text" name="experiment5" id="exp"></td>
            <td><input type="number" name="co5"></td>
            <td><input type="number" name="rubric5-1"></td>
            <td><input type="number" name="rubric5-2"></td>
            <td><input type="number" name="rubric5-3"></td>
            <td><input type="number" name="rubric5-4"></td>
            <td><input type="number" name="rubric5-5"></td>
            <td><input type="number" name="total5"></td>
            <td><input type="checkbox" name="student5"></td>
            <td><input type="checkbox" name="faculty5"></td>
        </tr>
        <tr>
            <td>6<!--<input type="text" name="slno6">--></td>
            <td><input type="date" name="date6"></td>
            <td><input type="text" name="experiment6" id="exp"></td>
            <td><input type="number" name="co6"></td>
            <td><input type="number" name="rubric6-1"></td>
            <td><input type="number" name="rubric6-2"></td>
            <td><input type="number" name="rubric6-3"></td>
            <td><input type="number" name="rubric6-4"></td>
            <td><input type="number" name="rubric6-5"></td>
            <td><input type="number" name="total6"></td>
            <td><input type="checkbox" name="student6"></td>
            <td><input type="checkbox" name="faculty6"></td>
        </tr>
        <tr>
            <td>7<!--<input type="text" name="slno7">--></td>
            <td><input type="date" name="date7"></td>
            <td><input type="text" name="experiment7" id="exp"></td>
            <td><input type="number" name="co7"></td>
            <td><input type="number" name="rubric7-1"></td>
            <td><input type="number" name="rubric7-2"></td>
            <td><input type="number" name="rubric7-3"></td>
            <td><input type="number" name="rubric7-4"></td>
            <td><input type="number" name="rubric7-5"></td>
            <td><input type="number" name="total7"></td>
            <td><input type="checkbox" name="student7"></td>
            <td><input type="checkbox" name="faculty7"></td>
        </tr>
        <tr><td colspan="4"><button  id="addrow" onclick="addRow(event)">Add Row</button></td>
        <td colspan="8"><button id="delrow" onclick="delRow(event)">Delete Row</button></td></tr>

    </table>
    </table>
    <br><br>
    <table border cellspacing="5">
        <tr><td colspan="12" style="text-align: left;"><b>Open Ended Project</b></td></tr>
        <tr>
            <td rowspan="3"><b>Sl No</b></td>
            <td rowspan="3"><b>Date of Project</b></td>
            <td rowspan="3"><b>Project</b></td>
            <td rowspan="3" id="c"><b>CO</b></td>
            <td colspan="6">
                <b>Marks Awarded for lab Work</b>
            <td rowspan="2" colspan="2"><b>Signature</b></td>
        <tr>
            <td colspan="5"><b>Rubrics</b></td>
            <td rowspan="2"><b>TOTAL</b></td>
        </tr>
        <tr id="no">
            <td>1</td>
            <td>2</td>
            <td>3</td>
            <td>4</td>
            <td>5</td>
            <td><b>Student</b></td>
            <td><b>Faculty</b></td>
        </tr>
        </td>
        </tr>
        <tr>
            <td>1<!--<input type="text" name="slno1">--></td>
            <td><input type="date" name="t2date1"></td>
            <td><input type="text" name="t2experiment1" id="exp"></td>
            <td><input type="number" name="t2co1"></td>
            <td><input type="number" name="t2rubric1-1"></td>
            <td><input type="number" name="t2rubric1-2"></td>
            <td><input type="number" name="t2rubric1-3"></td>
            <td><input type="number" name="t2rubric1-4"></td>
            <td><input type="number" name="t2rubric1-5"></td>
            <td><input type="number" name="t2total1"></td>
            <td><input type="checkbox" name="t2student1"></td>
            <td><input type="checkbox" name="t2faculty1"></td>
        </tr>
        <tr><td colspan="12">
            <!-- <input type="text" name="" id="t2last"> -->
        </td></tr>

        </table>
        <br><br>
        <table border="" cellpadding=""cellspacing="0">
            <tr><td colspan="12" style="text-align: left;"><b>Lab Exam</b></td></tr>
            <tr>
                <td rowspan="3"><b>Sl No</b></td>
                <td rowspan="3"><b>Date of Exam</b></td>
                <td rowspan="3"><b>Exam</b></td>
                <td rowspan="3" id="c"><b>CO</b></td>
                <td colspan="6">
                    <b>Marks Awarded for lab Work</b>
                <td rowspan="2" colspan="2"><b>Signature</b></td></tr>
            <tr>
                <td colspan="5"><b>Rubrics</b></td>
                <td rowspan="2"><b>TOTAL</b></td>
            </tr>
            <tr id="no">
                <td>1</td>
                <td>2</td>
                <td>3</td>
                <td>4</td>
                <td>5</td> <td><b>Student</b></td>
                <td><b>Faculty</b></td>
            </tr>
            </td>
            </tr>
            <tr>
                <td>1<!--<input type="text" name="slno1">--></td>
                    <td><input type="date" name="t3date1"></td>
                    <td><input type="text" name="exam1" id="exp"></td>
                    <td><input type="number" name="t3co1"></td>
                  <td><input type="number" name="t3rubric1-1"></td>
                  <td><input type="number" name="t3rubric1-2"></td>
                  <td><input type="number" name="t3rubric1-3"></td>
                  <td><input type="number" name="t3rubric1-4"></td>
                  <td><input type="number" name="t3rubric1-5"></td>
                  <td><input type="number" name="t3total1"></td>
                <td><input type="checkbox" name="t3student1"></td>
                <td><input type="checkbox" name="t3faculty1"></td>
            </tr>
            <tr>
                <td>2<!--<input type="text" name="slno2">--></td>
                <td><input type="date" name="t3date2"></td>
                <td><input type="text" name="exam2" id="exp"></td>
                <td><input type="number" name="t3co2"></td>
                <td><input type="number" name="t3rubric2-1"></td>
                <td><input type="number" name="t3rubric2-2"></td>
                <td><input type="number" name="t3rubric2-3"></td>
                <td><input type="number" name="t3rubric2-4"></td>
                <td><input type="number" name="t3rubric2-5"></td>
                <td><input type="number" name="t3total2"></td>
                <td><input type="checkbox" name="t3student2"></td>
                <td><input type="checkbox" name="t3faculty2"></td>
            </tr>
            <tr>
                <td>3<!--<input type="text" name="slno3">--></td>
                <td><input type="date" name="t3date3"></td>
                <td><input type="text" name="exam3" id="exp"></td>
                <td><input type="number" name="t3co3"></td>
                <td><input type="number" name="t3rubric3-1"></td>
                <td><input type="number" name="t3rubric3-2"></td>
                <td><input type="number" name="t3rubric3-3"></td>
                <td><input type="number" name="t3rubric3-4"></td>
                <td><input type="number" name="t3rubric3-5"></td>
                <td><input type="number" name="t3total3"></td>
                <td><input type="checkbox" name="t3student3"></td>
                <td><input type="checkbox" name="t3faculty3"></td>
            </tr>
                
            <tr><td colspan="12">
                <!-- <input type="" name="" id="t2last"> -->
            </td></tr>
            
            </table>
            <br><br>
            <center><table border="" cellspacing="0" cellpadding="" >
                <tr>
                    <td colspan="10" style="text-align: left;"><b>Final Assessment</b></td>
                </tr>
                        <tr><td colspan="2"></td>
                            <!-- <td></td> -->
                            <!-- <td></td> -->
                            <td>Maximum Marks </td>
                            <td>Marks Awarded</td>
                            <tr><td rowspan="2" colspan="2" style="height:30px ;">Attendance</td></tr>
                           <td>15</td> 
                           <td><input type="text" name="final1" id=""></td>
                        </tr>
                       <tr>
                        <td rowspan="3" colspan="">Formattive Assessment &nbsp;&nbsp;</td>
                       </tr>
                       <tr>
                           <td> Lab Work</td>
                           <td>37.5</td>
                           <td style="height: 30px;"><input type="text" name="final2" id=""></td>
                        </tr>
                        <tr><td>Open Ended Project&nbsp;&nbsp;</td>
                        <td>7.5</td>
                    <td style="height: 30px;"><input type="text" name="final3" id=""></td></tr>
                        <tr>
                           <td rowspan="2">Summative Assessment&nbsp;&nbsp;</td>
                       </tr>
                       <tr><td>Lab Exam</td>
                    <td>15</td>
                <td style="height: 30px;"><input type="text" name="final4" id=""></td></tr>
                    <tr><td colspan="2">Total Marks</td>
                    <td>75</td>
                <td style="height: 30px;"><input type="text" name="final5" id=""></td></tr>
                    </table><br><br><br>
                    <input type="submit" value="submit" name="submit"><br><br></center></form>
    <script>
        // Function to check if the user is an admin
        // function isAdmin() {
        //     return confirm("Are you an admin?");
        // }

        // // Function to enable or disable input fields based on admin status
        // function toggleAdminFields() {
        //     const isAdminUser = isAdmin();
        //     const adminFields = document.querySelectorAll('input[name^="rubric"],input[name^="t2rubric"],input[name^="t3rubric"], input[name^="total"],input[name^="t2total"],input[name^="t3total"], input[name^="faculty"], input[name^="t2faculty"], input[name^="t3faculty"],input[name^="final"]');
        //     const nonAdminFields = document.querySelectorAll('input:not([name^="rubric"]):not([name^="t2rubric"]):not([name^="t3rubric"]):not([name^="total"]):not([name^="t2total"]):not([name^="t3total"]):not([name^="faculty"]):not([name^="t2faculty"]):not([name^="t3faculty"]):not([name^="final"])');
        //     adminFields.forEach(field => {
        //         field.disabled = !isAdminUser;
        //     });

        //     nonAdminFields.forEach(field => {
        //         field.disabled = isAdminUser;
        //     });

        //     // Redirect to another file if the user is an admin
        //     if (isAdminUser) {
        //         window.location.href = "login.php";
        //     }
        // }

        // Function to add a new row to the table
        function addRow(event) {
            event.preventDefault();
            const table = document.getElementById('t1');
            const rowCount = table.rows.length - 4; // Adjust for header rows and button row
            const newRow = table.insertRow(rowCount + 3);
            newRow.innerHTML = `
                <td>${rowCount + 1}</td>
                <td><input type="date" name="date${rowCount + 1}"></td>
                <td><input type="text" name="experiment${rowCount + 1}" id="exp"></td>
                <td><input type="number" name="co${rowCount + 1}"></td>
                <td><input type="number" name="rubric${rowCount + 1}-1"></td>
                <td><input type="number" name="rubric${rowCount + 1}-2"></td>
                <td><input type="number" name="rubric${rowCount + 1}-3"></td>
                <td><input type="number" name="rubric${rowCount + 1}-4"></td>
                <td><input type="number" name="rubric${rowCount + 1}-5"></td>
                <td><input type="number" name="total${rowCount + 1}" oninput="calculateTotal(this)"></td>
                <td><input type="checkbox" name="student${rowCount + 1}"></td>
                <td><input type="checkbox" name="faculty${rowCount + 1}"></td>
            `;
            // toggleAdminFields(); // Reapply admin field settings to the new row
        }

        // Function to delete the last row from the table
        function delRow(event) {
            event.preventDefault();
            const table = document.getElementById('t1');
            const rowCount = table.rows.length - 3; // Adjust for header rows and button row
            if (rowCount > 1) { // Ensure there is at least one row to delete
                table.deleteRow(rowCount + 1);
            }
            else {
                alert("Cannot delete the last row");
            }
        }

        // Function to calculate the total marks for each row
        // function calculateTotal(element) {
        //     const row = element.parentElement.parentElement;
        //     const rubrics = row.querySelectorAll('input[name^="rubric"]');
        //     let total = 0;
        //     rubrics.forEach(rubric => {
        //         total += parseInt(rubric.value) || 0;
        //     });
        //     row.querySelector('input[name^="total"]').value = total;
        // }

        // Function to handle input fields of type text
        // function handleTextInputs() {
        //     const textInputs = document.querySelectorAll('input[type="text"]');
        //     textInputs.forEach(input => {
        //         input.addEventListener('input', () => {
        //             // Add your logic here to handle text input changes
        //             console.log(`Input changed: ${input.name} = ${input.value}`);
        //         });
        //     });
        // }
        
        // Call the function on page load
        window.onload = () => {
            // toggleAdminFields();
            handleTextInputs();
            // logform();
        };
    </script>
    <!-- <script>
    document.querySelector('form').addEventListener('submit', function(event) {
        var inputs = document.querySelectorAll('input:not([disabled]):not([type="checkbox"]):not([type="submit"]):not([style*="display: none"])');
        var allFilled = true;

        for (var i = 0; i < inputs.length; i++) {
            if (!inputs[i].value) {
                allFilled = false;
                inputs[i].focus();
                break;
            }
        }

        if (!allFilled) {
            alert('Please fill in all active fields.');
            event.preventDefault();
        }
    });
    </script> -->
    <script>
    function delRow(event) {
        event.preventDefault();
        const table = document.getElementById('t1');
        const rowCount = table.rows.length - 3; // Adjust for header rows and button row
        if (rowCount > 1) { // Ensure there is at least one row to delete
            table.deleteRow(rowCount + 1);
        } else {
            alert("Cannot delete the last row");
        }
    }
    </script>
    <!-- <script>
    function isAlphabet(input) {
        var regex = /^[a-zA-Z ]+$/;
        return regex.test(input);
    }

    function validateTextInputs() {
        var textInputs = document.querySelectorAll('input[type="text"]');
        for (var i = 0; i < textInputs.length; i++) {
            if (!isAlphabet(textInputs[i].value)) {
                alert('Please enter only alphabets in text fields.');
                textInputs[i].focus();
                return false;
            }
        }
        return true;
    }

    document.querySelector('form').addEventListener('submit', function(event) {
        if (!validateTextInputs()) {
            event.preventDefault();
        }
    });
    </script> -->

    <script>
        const hamburger = document.getElementById('hamburger');
        const navMenu = document.getElementById('nav-menu');

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
    </script>
</body>
</html>