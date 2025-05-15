from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify
from Forms import CreateUserForm,CreateUserInfo,Login,Update,Wishlist,Reporting
import shelve,User,UserInfo,Staff,hashlib, pyotp, qrcode, base64, io, two_fa, List, os, uuid, populatebins, Report, Feedback
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'asdsdasd dasdasd'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure the uploads directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# This is a temporary storage that will come in use during login to temporary store user info
db = shelve.open('temp.db','c')
db.close()

"""Web App Routing"""



# Before Login Homepage
@app.route('/')
def before_login():
    return render_template('index.html')

@app.route('/aboutUs')
def aboutUs():
    return render_template('aboutUs.html')

@app.route('/mission')
def mission():
    return render_template('mission.html')

@app.route('/feedbackb4')
def feedbackb4():
    return render_template('feedback before.html')

@app.route('/donate',  methods=["GET", "POST"])
def donate():
    if request.method == "POST":
        session["donation_amount"] = request.form.get("donation_amount")
        session["other_amount_value"] = request.form.get("other_amount_value")
        return redirect(url_for('payment'))
    return render_template('donate.html')

@app.route('/donate1',  methods=["GET", "POST"])
def donate1():
    if request.method == "POST":
        session["donation_amount"] = request.form.get("donation_amount")
        session["other_amount_value"] = request.form.get("other_amount_value")
        return redirect(url_for('payment'))
    return render_template('donate1.html')

@app.route("/confirmation")
def confirmation():
    
    return render_template(
        'confirmation.html'
    )

@app.route("/payment", methods=["GET", "POST"])
def payment():
    
    donate_amount = session["donation_amount"]
    other_amount_value = session["other_amount_value"]

    if request.method == "POST":
        # Process the payment (e.g., save to database, charge via payment gateway)
        # For now, we'll just redirect to the confirmation page
        return render_template('confirmation.html')

    # Store form data in session
    session["first_name"] = request.form.get("first-name")
    session["last_name"] = request.form.get("last-name")
    session["email"] = request.form.get("email")
    session["donation_amount"] = request.form.get("donation_amount")
    session["other_amount_value"] = request.form.get("other_amount_value")

    

    print(donate_amount)
    print(other_amount_value)

    return render_template(
        'payment.html',
        donate_amount= donate_amount,
        other_amount_value=other_amount_value
    )



# Login
@app.route('/login',methods=['GET','POST'])
def login():
    login_form = Login(request.form)
    if request.method == "POST" and login_form.validate():

        email = login_form.email.data
        password = login_form.password.data
        # hash the password input by the user during login
        h = hashlib.new("SHA256")
        h.update(password.encode())
        login_password = h.hexdigest()

        print(email)
        print(login_password)



        users_dict = {}
        db = shelve.open('user.db','c')

        try:
            users_dict = db['Users']
        except:
            print("Error in receiving users from users.db")
            message = "There is Currently No User Created"
            return render_template('login.html',form=login_form,message = message,message2="")
        
        users_dict = db['Users']

        db.close()

        user = users_dict.get(email,"Not_Found")

        if user == "Not_Found":
            # since user not found, open staff db to see if its a staff instead, if it is also not a staff, show message 2



            
            staff_dict = {}
            db = shelve.open('Staff','c')


            try:
                staff_dict = db['Staff']
            except:
                print("Error in receiving users from users.db")
        
            staff_dict = db['Staff']

            db.close()

            staff = staff_dict.get(email,"Not_Found")

        

            # if staff == "Not_Found":
            if staff == "Not_Found":
                message2 = "The email or password you entered is incorrect"
                return render_template('login.html',form=login_form,message ="",message2=message2)
        
            else:
                stored_password = staff.get_password()
        
            if login_password != stored_password:
                message2 = "The email or password you entered is incorrect"
                return render_template('login.html',form=login_form,message ="",message2=message2)
        
            # temporary storing username and email details.
            staff_name = staff.get_first_name()
            temp_dict = {}

            db = shelve.open('temp.db','w')
            try:
                temp_dict = db['Temp']
        
            except:
                print("Error in retrieving info from temp.db")
        
            temp_dict = {"email":email,"username":staff_name}
            db['Temp'] = temp_dict

            db.close()
        
            return redirect(url_for('staff_login'))


        
        else:
            stored_password = user.get_password1()
        
        if login_password != stored_password:
            message2 = "The email or password you entered is incorrect"
            return render_template('login.html',form=login_form,message2=message2,message = "")

        # after validating that this is a user, Im going to retrieve the username of the user
        user_info_dict = {}
        try: 
            db_user = shelve.open('userInfo.db', 'r')
            user_info_dict = db_user['userInfo']

            db_user.close()
        
            userInfo = user_info_dict[email]
            username = userInfo.get_username()
        except:
            print("Error in receiving info from user_info.db")
            message = "Your User Info has been deleted / Your account has been temporary suspended."
            return render_template('login.html',form=login_form,message = message,message2="")

            

        # temporary storing username and email details.

        temp_dict = {}

        db = shelve.open('temp.db','w')
        try:
            temp_dict = db['Temp']
        
        except:
            print("Error in retrieving info from temp.db")
        
        temp_dict = {"email":email,"username":username}
        db['Temp'] = temp_dict

        # test code
        retrieve_temp = db['Temp']
        temp_email = retrieve_temp['email']
        temp_user = retrieve_temp['username']
        print(temp_email)
        print(temp_user)


        db.close()

        
        return redirect(url_for('verify_otp'))
    return render_template('login.html',form=login_form,message2="")


# Staff Login 
@app.route('/staff_login', methods=['GET', 'POST'])
def staff_login():
    
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()

    db = shelve.open('listing.db', 'c')
    listings = db.get('listings', {})
    db.close()

    def format_photo_path(photo):
        if photo:
            return url_for('static', filename=photo.lstrip('static/'))  # Ensures no double "static/"
        return None  # Return None if no photo

    # Process Borrow Listings
    borrow_listings = {
        listing_id: {
            **listing,
            'photo': format_photo_path(listing.get('photo'))
        }
        for listing_id, listing in listings.items() if listing.get('type') == 'borrow'
    }

    # Process Free Listings
    free_listings = {
        listing_id: {
            **listing,
            'photo': format_photo_path(listing.get('photo'))
        }
        for listing_id, listing in listings.items() if listing.get('type') == 'free'
    }

    return render_template('staff_homepage.html', borrow_listings=borrow_listings, free_listings=free_listings, username=temp_user,email=temp_email)

      
# Sign Up 
@app.route('/sign_up', methods=['GET', 'POST']) 
def sign_up():
    create_user_form = CreateUserForm(request.form) 

    if request.method == 'POST' and create_user_form.validate(): 
        users_dict = {}
        db = shelve.open('user.db','c')

        try:
            users_dict = db['Users']
            email = create_user_form.email.data
            if email in users_dict:
                message = "Email has been taken."
                return render_template('sign_up.html', form=create_user_form,message=message)
        except:
            print("Error in receiving users from users.db")

        # hashing the password to store it in db
    
        password = create_user_form.password1.data
        hash = hashlib.new("SHA256")
        
        hash.update(password.encode())
        password_hash = hash.hexdigest()
        print(password_hash)

        # end of hashing
        
        user = User.User(create_user_form.first_name.data, create_user_form.last_name.data,create_user_form.email.data ,password_hash,password_hash) 
        users_dict[user.get_email()] = user 
        db['Users'] = users_dict 
         # Test codes 
        users_dict = db['Users'] 
        user = users_dict[user.get_email()] 
        print(user.get_first_name(), user.get_last_name(), "was stored in user.db successfully with user_id ==", user.get_email()) 
 
        db.close()

        return redirect(url_for('user_info')) 
    return render_template('sign_up.html', form=create_user_form,message="") 


# User Info 
@app.route('/user_info', methods=['GET', 'POST']) 
def user_info(): 
    create_user_info_form = CreateUserInfo(request.form) 
    if request.method == 'POST' and create_user_info_form.validate(): 
        telephone = create_user_info_form.phone_number.data
        print(telephone)
        try:
            phone_num = int(telephone)
        except ValueError:
            message = "This is not a valid number"
            return render_template('user_info.html', form=create_user_info_form,message=message)
        
        

        if len(telephone) != 8:
            message = "This is not a valid number"
            return render_template('user_info.html', form=create_user_info_form,message=message)
        
        if telephone.startswith('8') or telephone.startswith('9'):

            users_info_dict = {} 
            db = shelve.open('userInfo.db', 'c') 
 
            try: 
                users_info_dict = db['userInfo'] 
            except: 
                print("Error in retrieving Customers from customer.db.") 
 
            userInfo = UserInfo.UserInfo(create_user_info_form.username.data,create_user_info_form.gender.data,create_user_info_form.address.data,create_user_info_form.email.data,create_user_info_form.email.data,create_user_info_form.phone_number.data,create_user_info_form.bio.data,) 
            users_info_dict[userInfo.get_login_email()] = userInfo
            db['userInfo'] = users_info_dict
 
            db.close() 
        
            username = create_user_info_form.username.data
            email = create_user_info_form.email.data

        # hi there

            temp_dict = {}

            db = shelve.open('temp.db','w')
            try:
                temp_dict = db['Temp']
        
            except:
                print("Error in retrieving info from temp.db")
        
            temp_dict = {"email":email,"username":username}
            db['Temp'] = temp_dict
            db.close()

            return redirect(url_for('totp_setup')) 
        else:
            message = "This is not a valid number"
            return render_template('user_info.html', form=create_user_info_form,message=message)
    return render_template('user_info.html', form=create_user_info_form,message ="") 


# Set up 2FA Authenticator
@app.route('/2fa_setup', methods=['GET', 'POST'])
def totp_setup():
    # Retrieve temporary user info from the database
    db = shelve.open('temp.db', 'r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()

    # Check if the TOTP secret is already stored in the OTP database for this user
    otp_db = shelve.open('otp.db', 'c')
    try:
        otp_dict = otp_db['Otp']
    except:
        otp_dict = {}

    # If the user does not have a TOTP secret yet, generate one and store it in the database
    if temp_email not in otp_dict:
        totp_secret = pyotp.random_base32()
        # Store the TOTP secret in the OTP database immediately
        class_otp = two_fa.two_fa(temp_email, totp_secret)
        otp_dict[temp_email] = class_otp
        otp_db['Otp'] = otp_dict
        otp_db.close()
    else:
        # Retrieve the existing TOTP secret for the user
        totp_secret = otp_dict[temp_email].get_totp_secret()

    # Create a provisioning URI for the QR code
    provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name="NeighbourlyNest",
        issuer_name= temp_email
    )

    # Generate QR code from the provisioning URI
    qr = qrcode.QRCode(version=1, box_size=4, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    # Convert QR code to an image and encode it as base64
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    if request.method == "POST":
        # Get the OTP entered by the user
        user_otp = request.form.get('codeInput')

        # Validate the OTP using pyotp
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(user_otp):
            # OTP is correct, redirect to the login home page
            return redirect(url_for('login_home'))
        else:
            # OTP is incorrect, redirect back to the 2FA setup page
            flash("Invalid OTP. Please try again.", "error")
            return redirect(url_for('totp_setup'))

    # Render the 2FA setup page with the QR code and TOTP secret
    return render_template(
        "2fa_setup.html",
        qr_code_base64=qr_code_base64,
        totp_secret=totp_secret
    )


# Login Verify 6 Pin OTP
@app.route('/verify-otp', methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        # Retrieve the submitted OTP from the form
        user_otp = request.form.get("otpInput")

        # Retrieve temporary user info from the database
        db = shelve.open('temp.db', 'r')
        retrieve_temp = db['Temp']
        temp_email = retrieve_temp['email']
        temp_new_password = retrieve_temp.get('new_password')
        db.close()

        # Retrieve the stored TOTP secret for the user
        otp_dict = {}
        db = shelve.open('otp.db', 'r')
        try:
            otp_dict = db['Otp']
        except KeyError:
            print("Error: No OTP data found in the database.")
        finally:
            db.close()

        if temp_email not in otp_dict:
            # If no 2FA setup is found, redirect to the login page
            return redirect(url_for('login'))

        class_otp = otp_dict[temp_email]
        secret_code = class_otp.get_totp_secret()

        # Verify the OTP using the stored TOTP secret
        totp = pyotp.TOTP(secret_code)
        if totp.verify(user_otp):
            # OTP is valid, redirect to the login page
            if temp_new_password:
                users_dict = {}
                db = shelve.open('user.db', 'w')
                try:
                    users_dict = db['Users']
                except:
                    print("Error in receiving users from user.db")

                user = users_dict.get(temp_email, "Not_Found")
                if user != "Not_Found":
                    user.set_password1(temp_new_password)
                    user.set_password2(temp_new_password)
                    db['Users'] = users_dict
                    db.close()
                
                # Clear the temporary storage of password 
                db_temp = shelve.open('temp.db', 'w')
                temp_dict = db_temp['Temp']
                temp_dict.pop('new_password', None)  # Remove the temporary password
                db_temp['Temp'] = temp_dict
                db_temp.close()
                return redirect(url_for('login'))

            return redirect(url_for('login_home'))
        else:
            # OTP is invalid, show an error message
            error_message = "OTP is wrong"
            return render_template('verify_2fa.html', error_message=error_message)

    # Render the 2FA verification page for GET requests
    return render_template('verify_2fa.html')


# Forget Password 
@app.route('/update_user',methods =["GET","POST"])
def update_user():

    update_user_form = Login(request.form)
    if request.method == "POST" and update_user_form.validate():

        email = update_user_form.email.data
        new_password = update_user_form.password.data

        # hashing the password to store it in db


        hash = hashlib.new("SHA256")

        hash.update(new_password.encode())
        password_hash = hash.hexdigest()
        print(password_hash)

        # end of hashing

        db = shelve.open('temp.db', 'w')
        temp_dict = {}
        try:
            temp_dict = db['Temp']
        except:
            print("Error in retrieving info from temp.db")

        temp_dict['email'] = email
        temp_dict['new_password'] = password_hash  # Store the hashed password temporarily
        db['Temp'] = temp_dict
        db.close()

        return redirect(url_for('verify_otp'))

    return render_template('update_user.html',form = update_user_form,message1="")


# After Login Home 
@app.route('/login_home')
def login_home():
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()

    db = shelve.open('listing.db', 'c')
    listings = db.get('listings', {})
    db.close()

    def format_photo_path(photo):
        if photo:
            return url_for('static', filename=photo.lstrip('static/'))  # Ensures no double "static/"
        return None  # Return None if no photo

    # Process Borrow Listings
    borrow_listings = {
        listing_id: {
            **listing,
            'photo': format_photo_path(listing.get('photo'))
        }
        for listing_id, listing in listings.items() if listing.get('type') == 'borrow'
    }

    # Process Free Listings
    free_listings = {
        listing_id: {
            **listing,
            'photo': format_photo_path(listing.get('photo'))
        }
        for listing_id, listing in listings.items() if listing.get('type') == 'free'
    }

    return render_template('login_home.html', borrow_listings=borrow_listings, free_listings=free_listings, username=temp_user,email=temp_email)


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    return f"Search results for: {query}"


def validate_input(data, field, max_length=255):
    if not data or len(data) > max_length:
        return f"Invalid input for {field}. Ensure it's filled and does not exceed {max_length} characters."
    return None

# View Profile
@app.route('/user_retrieve_info')
def user_retrieve_info():
    # Retrieve username and email from temp db
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()

    # Fetch user info
    user_info_dict = {}
    db = shelve.open('userInfo.db','r')
    user_info_dict = db['userInfo']
    db.close()
    user_info = user_info_dict[temp_email]

    # Fetch all listings
    db = shelve.open('listing.db', 'c')
    listings = db.get('listings', {})
    db.close()

    def format_photo_path(photo):
        if photo:
            return url_for('static', filename=photo.lstrip('static/'))  # Ensures no double "static/"
        return None  # Return None if no photo

    # Combine Borrow and Free Listings
    combined_listings = {
        listing_id: {
            **listing,
            'photo': format_photo_path(listing.get('photo'))
        }
        for listing_id, listing in listings.items() if listing.get('owner') == temp_user
    }

    # Fetch wishlist
    see_wishlist = {}

    db = shelve.open('wishlist.db','c')

    try:
        see_wishlist = db['wishlist']
    except:
        print("No wishlist was created")
        return render_template('user_retrieve_info.html',user_info = user_info,username=temp_user,user_wishlist = "",combined_listings=combined_listings)
        
    see_wishlist = db['wishlist']

    db.close()

    user_wishlist = see_wishlist.get(temp_email,"None")
    if user_wishlist == "None":
        return render_template('user_retrieve_info.html',user_info = user_info,username=temp_user,user_wishlist = "",combined_listings=combined_listings)
        
    else:
        user_wishlist = see_wishlist[temp_email]

    return render_template('user_retrieve_info.html',user_info = user_info,username=temp_user,user_wishlist = user_wishlist, combined_listings=combined_listings)


# Update user profile

@app.route('/update_user_info',methods = ["GET","POST"])
def update_user_info():
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()

    update_user_info_form = CreateUserInfo(request.form)
    db_temp = shelve.open('temp.db','r')
    retrieve_temp = db_temp['Temp']
    temp_email = retrieve_temp['email']
    
    db_temp.close()

    if request.method == 'POST' and update_user_info_form.validate():

        user_info_dict = {}
        db = shelve.open('userInfo.db','w')
        user_info_dict = db['userInfo']
        user_info = user_info_dict.get(temp_email)
        user_info.set_username(update_user_info_form.username.data)
        user_info.set_gender(update_user_info_form.gender.data)
        user_info.set_address(update_user_info_form.address.data)
        user_info.set_email(update_user_info_form.email.data)
        user_info.set_phone_number(update_user_info_form.phone_number.data)
        user_info.set_bio(update_user_info_form.bio.data)

        db['userInfo'] = user_info_dict

        db.close()
        
        return redirect(url_for('user_retrieve_info'))
    
    else:
        user_info_dict = {}
        db = shelve.open('userInfo.db','r')
        user_info_dict = db['userInfo']
        db.close()

        user_info = user_info_dict.get(temp_email)
        update_user_info_form.username.data = user_info.get_username()
        update_user_info_form.gender.data = user_info.get_gender()
        update_user_info_form.address.data = user_info.get_address()
        update_user_info_form.email.data = user_info.get_email()
        update_user_info_form.phone_number.data = user_info.get_phone_number()
        update_user_info_form.bio.data = user_info.get_bio()
        


        return render_template('update_user_info.html',form=update_user_info_form, user_info = user_info,username=temp_user)

# this is when they want to create a new wishlist
@app.route('/create_wantlist',methods =["GET","POST"])
def create_wantlist():
    db_temp = shelve.open('temp.db','r')
    retrieve_temp = db_temp['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    
    create_wishlist_form = Wishlist(request.form)
    if request.method == "POST" and create_wishlist_form.validate():
        email = create_wishlist_form.email.data
        user_wishlist = {}
        db = shelve.open('wishlist.db','c')

        try:
            user_wishlist = db['wishlist']
        except:
            print("Error in receiving users from wishlist.db")
        
        wishlist = List.List(create_wishlist_form.email.data,create_wishlist_form.item.data,create_wishlist_form.description.data)

        user_wishlist[wishlist.get_email()] = wishlist

        db['wishlist'] = user_wishlist

        db.close()

        user_info_dict = {}

        db_user = shelve.open('userInfo.db', 'r')
        user_info_dict = db_user['userInfo']
        db_user.close()
        userInfo = user_info_dict[email]
        username = userInfo.get_username()

        # adding hans portion so that I can return his stuff as well

        # writing hans portion here 


        db = shelve.open('listing.db', 'c')
        listings = db.get('listings', {})
        db.close()

        def format_photo_path(photo):
            if photo:
                return url_for('static', filename=photo.lstrip('static/'))  # Ensures no double "static/"
            return None  # Return None if no photo

        # Process Borrow Listings
        borrow_listings = {
            listing_id: {
                **listing,
                'photo': format_photo_path(listing.get('photo'))
            }
            for listing_id, listing in listings.items() if listing.get('type') == 'borrow'
        }

        # Process Free Listings
        free_listings = {
            listing_id: {
                **listing,
                'photo': format_photo_path(listing.get('photo'))
            }
            for listing_id, listing in listings.items() if listing.get('type') == 'free'
        }

        combined_listings = {
        listing_id: {
            **listing,
            'photo': format_photo_path(listing.get('photo'))
        }
        for listing_id, listing in listings.items() if listing.get('owner') == temp_user
    }





        see_wishlist = {}

        db = shelve.open('wishlist.db','r')

        try:
            see_wishlist = db['wishlist']
        except:
            print("No wishlist was created")
            return render_template('user_retrieve_info.html',user_info = userInfo,username=username,user_wishlist = "",borrow_listings=borrow_listings,free_listings=free_listings, combined_listings = combined_listings)
        
        see_wishlist = db['wishlist']

        db.close()

        user_wishlist = see_wishlist[email]

        

        return render_template('user_retrieve_info.html',user_info = userInfo,username=username,user_wishlist = user_wishlist,borrow_listings=borrow_listings,free_listings=free_listings, combined_listings = combined_listings)

    
    return render_template('create_wishlist.html',form=create_wishlist_form, username = temp_user)


# Update wishlist 
@app.route('/update_wantlist',methods =["GET","POST"])
def update_wantlist():
    update_wishlist_form = Wishlist(request.form)

    # get temp details to retern since this is to go back to the homepage
    db_temp = shelve.open('temp.db','r')
    retrieve_temp = db_temp['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    
    db_temp.close()
    if request.method == "POST" and update_wishlist_form.validate():
        user_wishlist = {}
        db = shelve.open('wishlist.db','w')
        user_wishlist = db['wishlist']
        
        wish_info = user_wishlist.get(temp_email)
        wish_info.set_email(update_wishlist_form.email.data) 
        wish_info.set_item(update_wishlist_form.item.data)
        wish_info.set_description(update_wishlist_form.description.data)
        db['wishlist'] = user_wishlist
        db.close()

        db_user = shelve.open('userInfo.db', 'r')
        user_info_dict = db_user['userInfo']
        db_user.close()
        userInfo = user_info_dict[temp_email]
        username = userInfo.get_username()
    
        # adding hans portion so that I can return his stuff as well

        # writing hans portion here 


        db = shelve.open('listing.db', 'c')
        listings = db.get('listings', {})
        db.close()

        def format_photo_path(photo):
            if photo:
                return url_for('static', filename=photo.lstrip('static/'))  # Ensures no double "static/"
            return None  # Return None if no photo

        # Process Borrow Listings
        borrow_listings = {
            listing_id: {
                **listing,
                'photo': format_photo_path(listing.get('photo'))
            }
            for listing_id, listing in listings.items() if listing.get('type') == 'borrow'
        }

        # Process Free Listings
        free_listings = {
            listing_id: {
                **listing,
                'photo': format_photo_path(listing.get('photo'))
            }
            for listing_id, listing in listings.items() if listing.get('type') == 'free'
        }

        combined_listings = {
        listing_id: {
            **listing,
            'photo': format_photo_path(listing.get('photo'))
        }
        for listing_id, listing in listings.items() if listing.get('owner') == temp_user
    }




        see_wishlist = {}

        db = shelve.open('wishlist.db','r')

        try:
            see_wishlist = db['wishlist']
        except:
            print("Error in receiving users from users.db")
        
        see_wishlist = db['wishlist']

        db.close()

        user_wishlist = see_wishlist[temp_email]

        return render_template('user_retrieve_info.html',user_info = userInfo,username=username,user_wishlist = user_wishlist,borrow_listings=borrow_listings,free_listings=free_listings, combined_listings = combined_listings)

        
    
    else:
        user_wishlist = {}
        db = shelve.open('wishlist.db','r')
        user_wishlist = db['wishlist']
        db.close()
        wish_info = user_wishlist.get(temp_email)
        update_wishlist_form.email.data = wish_info.get_email()
        update_wishlist_form.item.data = wish_info.get_item()
        update_wishlist_form.description.data = wish_info.get_description()

        return render_template('update_wishlist.html',form=update_wishlist_form)



# Delete Wishlist

@app.route('/delete_wantlist',methods =["GET","POST"])
def delete_wishlist():
    db_temp = shelve.open('temp.db','r')
    retrieve_temp = db_temp['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db_temp.close()
    if request.method == "POST":
        user_wishlist = {}
        db = shelve.open('wishlist.db','w')
        user_wishlist = db['wishlist']

        wishlist = user_wishlist.get(temp_email,"None")
        if wishlist == "None":
            pass
            # put a message here later
            db.close()
        else:
            user_wishlist.pop(temp_email)
            db['wishlist'] = user_wishlist
      
            db.close()

            

            db_user = shelve.open('userInfo.db', 'r')
            user_info_dict = db_user['userInfo']
            db_user.close()
            userInfo = user_info_dict[temp_email]
            username = userInfo.get_username()

            # adding hans portion so that I can return his stuff as well

            # writing hans portion here 


            db = shelve.open('listing.db', 'c')
            listings = db.get('listings', {})
            db.close()

            def format_photo_path(photo):
                if photo:
                    return url_for('static', filename=photo.lstrip('static/'))  # Ensures no double "static/"
                return None  # Return None if no photo

            # Process Borrow Listings
            borrow_listings = {
                listing_id: {
                    **listing,
                    'photo': format_photo_path(listing.get('photo'))
                }
                for listing_id, listing in listings.items() if listing.get('type') == 'borrow'
            }

            # Process Free Listings
            free_listings = {
                listing_id: {
                    **listing,
                    'photo': format_photo_path(listing.get('photo'))
                }
                for listing_id, listing in listings.items() if listing.get('type') == 'free'
            }

            combined_listings = {
            listing_id: {
                **listing,
                'photo': format_photo_path(listing.get('photo'))
            }
            for listing_id, listing in listings.items() if listing.get('owner') == temp_user
        }


            return render_template('user_retrieve_info.html',user_info = userInfo,username=username,user_wishlist = "",borrow_listings=borrow_listings,free_listings=free_listings, combined_listings = combined_listings)
        


# Royston Wishlist 
@app.route('/wishlist')
def wishlist():
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()

    with shelve.open("favorites.db") as db:
        favorites = db.get("favorites", {})
        user_favorites = favorites.get(temp_email, {})

    return render_template('wishlist.html', user_info=user_info, username=temp_user, favorited_listings=user_favorites)



# Create Listing
@app.route('/create_listing', methods=['GET', 'POST'])
def create_listing():
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        listing_type = request.form.get('type')
        availability_date = request.form.get('availability_date')
        availability_time = request.form.get('availability_time')

        errors = []
        for field, value in {'Title': title, 'Description': description, 'Category': category, 'Type': listing_type}.items():
            error = validate_input(value, field)
            if error:
                errors.append(error)

        if errors:
            return render_template('new_listing.html', errors=errors, user_info = user_info,username=temp_user)

        # File Upload Validation
        photo = request.files.get('photo')
        photo_path = None
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo_path = f"uploads/{filename}"
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        db = shelve.open('listing.db', 'c')
        listings = db.get('listings', {})

        listing_id = max(listings.keys(), default=0) + 1
        listings[listing_id] = {
            'owner' : temp_user,
            'title': title,
            'description': description,
            'category': category,
            'type': listing_type,
            'availability_date': availability_date,
            'availability_time': availability_time,
            'photo': photo_path
        }

        db['listings'] = listings
        db.close()

        return redirect(url_for('login_home'))

    return render_template('new_listing.html', user_info = user_info,username=temp_user)


# Update Listing
@app.route('/update_listing/<int:listing_id>', methods=['GET', 'POST'])
def update_listing(listing_id):
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()
    db = shelve.open('listing.db', 'c')
    listings = db.get('listings', {})

    if listing_id not in listings:
        db.close()
        return "Listing not found!", 404

    if request.method == 'POST':
        # Update listing details
        listings[listing_id]['title'] = request.form.get('title')
        listings[listing_id]['description'] = request.form.get('description')
        listings[listing_id]['category'] = request.form.get('category')
        listings[listing_id]['type'] = request.form.get('type')
        listings[listing_id]['availability_date'] = request.form.get('availability_date')
        listings[listing_id]['availability_time'] = request.form.get('availability_time')

        # Handle new photo upload
        photo = request.files.get('photo')
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo_path = f"uploads/{filename}"  # Store only relative path
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            listings[listing_id]['photo'] = photo_path  # Update photo

        db['listings'] = listings
        db.close()
        return redirect(url_for('login_home'))

    listing = listings.get(listing_id)
    db.close()
    return render_template('update_listing.html', listing=listing, listing_id=listing_id, user_info = user_info,username=temp_user)


# Delete Listing
@app.route('/delete_listing/<int:listing_id>', methods=['POST'])
def delete_listing(listing_id):
    db = shelve.open('listing.db', 'c')
    listings = db.get('listings', {})

    if listing_id in listings:
        del listings[listing_id]

    db['listings'] = listings
    db.close()
    return redirect(url_for('login_home'))


# Locate Bins
@app.route('/locate')
def locate():
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_user = retrieve_temp['username']
    db.close()

    db = shelve.open('bins.db')

    # Ensure 'bins' key exists in the database
    bins = db.get('bins', {})

    db.close()
    return render_template('locate.html', bins=bins, username = temp_user)

# Feedback
@app.route('/feedback', methods=["GET", "POST"])
def feedback():
    # Retrieve logged-in user's details
    db = shelve.open('temp.db', 'r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']  # Use email as a unique identifier
    temp_user = retrieve_temp['username']
    db.close()

    

    # Open feedback database
    db = shelve.open('feedback.db', writeback=True)
    if 'feedback' not in db:
        db['feedback'] = {}
    feedbacks = db['feedback']

    # Filter feedback to show only the logged-in user's feedback
    user_feedbacks = {key: value for key, value in feedbacks.items() if value.get('email') == temp_email}

    errors = []
    if request.method == 'POST':
        feedback_id = request.form.get('feedbackId')
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()

        # Validation checks
        if len(name) < 3:
            errors.append("Name must be at least 3 characters long.")
        if '@' not in email or '.' not in email:
            errors.append("Invalid email format.")
        if len(message) < 10:
            errors.append("Message must be at least 10 characters long.")

        if errors:
            db.close()
            return render_template('feedback.html', feedbacks=user_feedbacks, errors=errors, username=temp_user)

        # Save feedback with user association
        if feedback_id and feedback_id in feedbacks:
            feedbacks[feedback_id] = {'name': name, 'email': email, 'message': message}
        else:
            new_id = str(uuid.uuid4())
            feedbacks[new_id] = {'name': name, 'email': email, 'message': message}

        db['feedback'] = feedbacks
        db.close()

        dc = shelve.open('staff_feedback.db', "c")
        feedback_dict = {}
        try: 
            feedback_dict = dc['feedback'] 
        except: 
            print("Error in retrieving feedbacks from feedback.db.")

        feedback_info = Feedback.Feedback(feedback_id,name,email,message)

        feedback_dict[temp_email] = feedback_info

        dc['feedback'] = feedback_dict


        db.close()
        return redirect('/feedback')

    db.close()


    return render_template('feedback.html', feedbacks=user_feedbacks, errors=[], username=temp_user)


# Edit Feedback 
@app.route('/edit_feedback/<id>')
def edit_feedback(id):
    db = shelve.open('feedback.db', 'r')
    feedbacks = db.get('feedback', {})
    feedback = feedbacks.get(id, None)
    db.close()

    if feedback:
        return jsonify({'name': feedback['name'], 'email': feedback['email'], 'message': feedback['message']})
    else:
        return jsonify({'error': 'Feedback not found'}), 404

# Delete Feedback
@app.route('/delete_feedback/<id>', methods=["POST"])
def delete_feedback(id):
    db = shelve.open('feedback.db', writeback=True)
    if 'feedback' in db and id in db['feedback']:
        del db['feedback'][id]
    db.close()
    return '', 204


""" Favourite Handling"""
def update_favorites(listing_id, action, user_email):
    """ Adds or removes a listing from favorites.db associated with the user's email """
    with shelve.open("favorites.db", writeback=True) as db:
        if "favorites" not in db:
            db["favorites"] = {}

        favorites = db["favorites"]
        
        # Ensure the user has their own favorites dictionary
        if user_email not in favorites:
            favorites[user_email] = {}

        user_favorites = favorites[user_email]
        print(f"Current favorites before update for {user_email}: {user_favorites}")  # Debugging log

        if action == "add":
            db_listings = shelve.open("listing.db")
            listings = db_listings.get("listings", {})
            print(f"Listings in listing.db: {listings}")  # Debugging log

            # Convert listing_id to integer for lookup
            listing_id_int = int(listing_id)
            if listing_id_int in listings:  # Check if the integer key exists
                # Format the photo path to include the 'static/' prefix
                listing = listings[listing_id_int]
                if "photo" in listing and listing["photo"]:
                    listing["photo"] = f"static/{listing['photo']}"
                user_favorites[str(listing_id)] = listing  # Add the listing to user's favorites
                print(f"Added listing {listing_id} to favorites for {user_email}")  # Debugging log
            else:
                print(f"Listing ID {listing_id} not found in listing.db")  # Debugging log
            db_listings.close()

        elif action == "remove" and str(listing_id) in user_favorites:
            del user_favorites[str(listing_id)]  # Remove the listing from user's favorites
            print(f"Removed listing {listing_id} from favorites for {user_email}")  # Debugging log

        # Explicitly write back the changes to the database
        db["favorites"] = favorites
        db.sync()  # Force synchronization to ensure changes are saved
        print("Updated favorites:", favorites)  # Debugging log


@app.route("/favorite/<int:listing_id>", methods=["POST"])
def favorite_item(listing_id):
    """ Handle AJAX requests for favoriting/unfavoriting items """
    print(f"Received request for listing ID: {listing_id}")   # Debugging log
    action = request.json.get("action")
    print(f"Action: {action}")  # Debugging log

    if action not in ["add", "remove"]:
        return jsonify({"error": "Invalid action"}), 400

    # Retrieve logged-in user's details
    db = shelve.open('temp.db', 'r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']  # Use email as a unique identifier
    db.close()

    update_favorites(listing_id, action, temp_email)
    return jsonify({"success": True})


# Borrow
@app.route('/borrow')
def borrow():
    db = shelve.open('temp.db', 'r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']  # Use email as a unique identifier
    temp_user = retrieve_temp['username']
    db.close()

    db = shelve.open('listing.db', 'c')
    listings = db.get('listings', {})
    db.close()

    # Retrieve favorited listings
    with shelve.open("favorites.db") as favorites_db:
        favorited_listings = favorites_db.get("favorites", {}).get(temp_email, {})

    def format_photo_path(photo):
        if photo:
            return url_for('static', filename=photo.lstrip('static/'))  # Ensures no double "static/"
        return None  # Return None if no photo

    # Process Borrow Listings
    borrow_listings = {
        listing_id: {
            **listing,
            'photo': format_photo_path(listing.get('photo'))
        }
        for listing_id, listing in listings.items() if listing.get('type') == 'borrow'
    }

    return render_template("borrow.html", borrow_listings=borrow_listings, favorited_listings=favorited_listings, username=temp_user)


# Free
@app.route('/free')
def free():
    db = shelve.open('temp.db', 'r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']  # Use email as a unique identifier
    temp_user = retrieve_temp['username']
    db.close()

    db = shelve.open('listing.db', 'c')
    listings = db.get('listings', {})
    db.close()

    # Retrieve favorited listings
    with shelve.open("favorites.db") as favorites_db:
        favorited_listings = favorites_db.get("favorites", {}).get(temp_email, {})

    def format_photo_path(photo):
        if photo:
            return url_for('static', filename=photo.lstrip('static/'))  # Ensures no double "static/"
        return None  # Return None if no photo

    # Process Free Listings
    free_listings = {
        listing_id: {
            **listing,
            'photo': format_photo_path(listing.get('photo'))
        }
        for listing_id, listing in listings.items() if listing.get('type') == 'free'
    }

    return render_template("free.html", free_listings=free_listings, favorited_listings=favorited_listings, username=temp_user)


# Admin Dashboard
@app.route('/dashboard')
def dashboard():
    db = shelve.open('temp.db', 'r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']  # Use email as a unique identifier
    temp_user = retrieve_temp['username']
    db.close()

    user_info_dict = {}
    db = shelve.open('userInfo.db','r')
    user_info_dict = db['userInfo']
    db.close()


    info_list = []
    for key in user_info_dict:
        info = user_info_dict.get(key)
        info_list.append(info)

    # Add the count of listings
    db = shelve.open('listing.db', 'c')
    listings = db.get('listings', {})
    db.close()
    listing_count = len(listings)

    report_dict = {}
    db = shelve.open('report.db','c')
    try:
        report_dict = db['Report']
    except:
        print("No report was created")
        return render_template('dashboard.html',count_report = 0, report_list="", username = temp_user, count=len(info_list), info_list=info_list, listing_count=listing_count)


    db.close()

    report_list = []
    for key in report_dict:
        info = report_dict.get(key)
        report_list.append(info)
    return render_template('dashboard.html',count_report=len(report_list), report_list=report_list, username = temp_user, count=len(info_list), info_list=info_list, listing_count=listing_count)


# Count the amount of listing
@app.route('/count_listings')
def count_listings():
    db = shelve.open('listing.db', 'c')
    listings = db.get('listings', {})
    db.close()
    
    # Get the count of all listings
    listing_count = len(listings)
    
    return jsonify({"total_listings": listing_count})


# Delete User Account 
@app.route('/delete_user_info',methods =["GET","POST"])
def delete_user_info():
    if request.method == "POST":

        # Add the count of listings
        db = shelve.open('listing.db', 'r')
        listings = db.get('listings', {})
        db.close()
        listing_count = len(listings)

        db = shelve.open('temp.db', 'r')
        retrieve_temp = db['Temp']
        temp_email = retrieve_temp['email']  # Use email as a unique identifier
        temp_user = retrieve_temp['username']
        db.close()


        email = request.form.get('email')
        print(email)
        user_info_dict = {}
        db = shelve.open('userInfo.db','w')
        user_info_dict = db['userInfo']
        user_info_dict.pop(email)
        db['userInfo'] = user_info_dict

        # after deleting the email's user_info
        new_user_info_dict = {}
        new_user_info_dict = db['userInfo']
        db.close()

        info_list = []
        for key in new_user_info_dict:
            info = new_user_info_dict.get(key)
            info_list.append(info)

    return render_template('dashboard.html',count=len(info_list), info_list=info_list, listing_count=listing_count, username = temp_user)



# Report User (Non-Admin)
@app.route('/report_user',methods = ["GET","POST"])
def report_user():
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()

    report_form = Reporting(request.form)
    if request.method == "POST" and report_form.validate():
        email = report_form.report_email.data
        reason = report_form.report_option.data
        other_reason = report_form.report_other.data
        description = report_form.report_description.data
        report_dict = {}
        db = shelve.open('report.db','c')
        try:
            report_dict = db['Report']
        except:
            print("Error in receiving users from users.db")
        # continue from here

        report = Report.Report(email,reason,other_reason,description)
        report_dict[email] = report
        db['Report'] = report_dict

        db.close()

        # calling temp storage to retrieve username
        db = shelve.open('temp.db','r')
        retrieve_temp = db['Temp']
        temp_email = retrieve_temp['email']
        temp_user = retrieve_temp['username']
        db.close()

        db = shelve.open('listing.db', 'c')
        listings = db.get('listings', {})
        db.close()

        def format_photo_path(photo):
            if photo:
                return url_for('static', filename=photo.lstrip('static/'))  # Ensures no double "static/"
            return None  # Return None if no photo

        # Process Borrow Listings
        borrow_listings = {
            listing_id: {
                **listing,
                'photo': format_photo_path(listing.get('photo'))
            }
            for listing_id, listing in listings.items() if listing.get('type') == 'borrow'
        }

        # Process Free Listings
        free_listings = {
            listing_id: {
                **listing,
                'photo': format_photo_path(listing.get('photo'))
            }
            for listing_id, listing in listings.items() if listing.get('type') == 'free'
        }

        return render_template('login_home.html', borrow_listings=borrow_listings, free_listings=free_listings, username=temp_user,email=temp_email)
    return render_template('/report.html',form=report_form, username = temp_user)


# Admin View Report
@app.route('/view_report')
def view_report():
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()

    report_dict = {}
    db = shelve.open('report.db','c')
    try:
        report_dict = db['Report']
    except:
        print("No report was created")
        return render_template('/view_report.html',count = 0, report_list="", username = temp_user)


    db.close()

    report_list = []
    for key in report_dict:
        info = report_dict.get(key)
        report_list.append(info)
    return render_template('/view_report.html',count=len(report_list), report_list=report_list, username = temp_user)


# Dashboard Feedback
@app.route('/dashboard_feedback')
def dashboard_feedback():
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()

    see_feedback = {}

    db = shelve.open('staff_feedback.db', 'r')
    see_feedback = db['feedback']
    db.close()

    feedbacklist = []
    
    for key in see_feedback :
        feedback = see_feedback.get(key)
        feedbacklist.append(feedback)

    return render_template('dashboard_feedback.html', username = temp_user, count = len(feedbacklist), feedbacklist = feedbacklist)

    
# Collection Appointment 
@app.route('/booking/<int:listing_id>', methods=['GET', 'POST'])
def booking(listing_id):
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()

    db = shelve.open('listing.db', 'c')
    listings = db.get('listings', {})
    listing_get = listings[listing_id]
    db.close()
    if request.method == 'POST':
        print("Form data received:", request.form)

        # Get only the essential data that's actually being sent
        selected_date = request.form.get('selectedDate')
        selected_time = request.form.get('selectedTime')

        # Save the booking to the database
        db = shelve.open('bookings.db', 'c')

        bookings = db.get('bookings', {})
        booking_id = max(bookings.keys(), default=0) + 1
        bookings[booking_id] = {
            'listing_id': booking_id,
            'user_name': temp_user,
            'user_email': temp_email,
            'selected_date': selected_date,
            'selected_time': selected_time
        }
        db['bookings'] = bookings

        # Booking DB Key = bookings, booking_dict = booking_id
        # Redirect to bookings page
        flash('Your booking has been successfully created!', 'success')
        return redirect(url_for('show_bookings'))

    # If it's a GET request, render the booking form
    return render_template('booking.html', listings = listing_get, username = temp_user)

@app.route('/bookings')
def show_bookings():
    db = shelve.open('temp.db','r')
    retrieve_temp = db['Temp']
    temp_email = retrieve_temp['email']
    temp_user = retrieve_temp['username']
    db.close()

    db = shelve.open('bookings.db', 'c')
    bookings = db.get('bookings', {})
    return render_template('viewbooking.html', bookings=bookings, username = temp_user)


if __name__ == '__main__':
    app.run(debug = True)