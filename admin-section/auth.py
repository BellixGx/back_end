# # the standard input according to the problem statement.
# import math
# numbers=[]
# n = int(input())
# table= []
# for i in range(n):
#     a, b = [int(j) for j in input().split()]
#     table.append([a, b])

# for i in range(n):  
#     sum2=0
#     for j in range(table[i][0], table[i][1]+1):
#         sum1=0
#         for k in range(1, j + 1):
#             print(j, k)
#             if j % k == 0:
#                 sum1 = sum1 + k # 1 + 3 = 4
#         if sum1 < j*2 : # 3
#             sum2 = sum2 + ( j*2 - sum1 ) # 1 + 5
#     numbers.append(sum2)

# for i in range(len(numbers)):
#     print(numbers[i])    

# import bcrypt

# def hash_password(password):
#     salt = bcrypt.gensalt()  # Generate a new salt for each hash
#     hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
#     return hashed.decode('utf-8')

# def verify_password(input_password, stored_hash):
#     return bcrypt.checkpw(input_password.encode('utf-8'), stored_hash.encode('utf-8'))

# # Example usage
# password = "@Anass2025@"
# hashed_password = hash_password(password)  # Store this in DB
# print(f"Hashed Password: {hashed_password}")

# # Verifying
# is_valid = verify_password("@Anass2025@", hashed_password)  # Should return True
# print(f"Password Valid: {is_valid}")

