import shelve,hashlib


class Staff():
    count_id = 0
    def __init__(self, first_name, last_name, email ,password1):
        Staff.count_id += 1
        self.__user_id = Staff.count_id
        self.__first_name = first_name
        self.__last_name = last_name
        self.__email = email
        self.__password = password1
        
        

    def get_user_id(self):
        return self.__user_id
    
    def get_first_name(self):
        return self.__first_name
    
    def get_last_name(self):
        return self.__last_name
    
    def get_email(self):
        return self.__email
    
    def get_password(self):
        return self.__password
    
    
    def set_user_id(self,user_id):
        self.__user_id = user_id
    
    def set_first_name(self,first_name):
        self.__first_name = first_name
    
    def set_last_name(self,last_name):
        self.__last_name = last_name

    def set_email(self,email):
        self.__email = email
    
    def set_password(self,password1):
        self.__password = password1
    


# hashing the password to store it in db
    
password = 'password'
hash = hashlib.new("SHA256")
        
hash.update(password.encode())
password_hash = hash.hexdigest()

# end of hashing

staff = Staff("Alex","Tan","alextan@gmail.com",password_hash)


staff_dict = {}
staff_dict[staff.get_email()] = staff
db = shelve.open('Staff','c')

db['Staff'] = staff_dict

db.close()