import random
print("******************************")
print("   Welcome to the  Quizzer    ")
print("******************************")
username=input("Enter Your User Name : ")
is_playing=True
questions = {
    "What is the capital of Australia?": {
        "options": ("Sydney","Canberra","Melbourne","Perth"),
        "answer": "2"
    },
    "Which planet is known as the Red Planet?": {
        "options": ("Venus","Mars","Jupiter","Saturn"),
        "answer": "2"
    },
    "Who wrote Romeo and Juliet?": {
        "options": ("Charles Dickens","William Shakespeare","Jane Austen","Mark Twain"),
        "answer": "2"
    },
    "Which is the largest ocean on Earth?": {
        "options": ("Atlantic Ocean","Indian Ocean","Arctic Ocean","Pacific Ocean"),
        "answer": "4"
    },
    "What does CPU stand for?": {
        "options": ("Central Process Unit","Central Processing Unit","Computer Personal Unit","Control Processing Unit"),
        "answer": "2"
    },
    "Which language is primarily used for web development?": {
        "options": ("Python","C++","Java","JavaScript"),
        "answer": "4"
    },
    "What does HTML stand for?": {
        "options": ("Hyper Trainer Marking Language","Hyper Text Markup Language","High Text Machine Language","Hyper Text Machine Language"),
        "answer": "2"
    },
    "What principle states that certain pairs of physical properties cannot be simultaneously known with arbitrary precision?": {
        "options": ("Pauli Exclusion Principle","Heisenberg Uncertainty Principle","Aufbau Principle","De Broglie Hypothesis"),
        "answer": "2"
    },
    "Which law of thermodynamics introduces the concept of entropy?": {
        "options": ("Zeroth Law","First Law","Second Law","Third Law"),
        "answer": "3"
    },
    "What is the function of the enzyme helicase?": {
        "options": ("Synthesizes RNA primer","Unwinds DNA double helix","Joins Okazaki fragments","Adds nucleotides to DNA"),
        "answer": "2"
    },
    "Which particle has zero rest mass?": {
        "options": ("Electron","Proton","Photon","Neutron"),
        "answer": "3"
    },
    "Which data structure uses FIFO principle?": {
        "options": ("Stack","Queue","Tree","Graph"),
        "answer": "2"
    },
    "What is the time complexity of binary search?": {
        "options": ("O(n)","O(log n)","O(n log n)","O(1)"),
        "answer": "2"
    },
    "Which gas has the highest concentration in Earth's atmosphere?": {
        "options": ("Oxygen","Carbon Dioxide","Nitrogen","Hydrogen"),
        "answer": "3"
    },
    "What does RAM stand for?": {
        "options": ("Random Access Memory","Read Access Memory","Run Access Memory","Real-time Access Memory"),
        "answer": "1"
    },
    "Which sorting algorithm is the fastest on average?": {
        "options": ("Bubble Sort","Insertion Sort","Quick Sort","Selection Sort"),
        "answer": "3"
    },
    "Which organelle is known as the powerhouse of the cell?": {
        "options": ("Nucleus","Ribosome","Mitochondria","Golgi Apparatus"),
        "answer": "3"
    },
    "What is the derivative of sin(x)?": {
        "options": ("cos(x)","-cos(x)","sin(x)","-sin(x)"),
        "answer": "1"
    }
}
def print_options(options):
    for i, option in enumerate(options, 1):
        print(f"{i}. {option}")
def check_answer(user_ans, options, correct_ans):
    user_ans = user_ans.strip().lower()

    # get correct option text
    correct_option = options[int(correct_ans) - 1].lower()

    # check if user entered number
    if user_ans.isdigit():
        return user_ans == correct_ans

    # otherwise compare text
    return user_ans == correct_option        
# -------- START --------
start = input("Do you want to play the quiz? (Yes/No): ")
sys_start = start.capitalize()

if sys_start != "Yes":
    print("Exiting game.")
else:
    is_playing = True

    while is_playing:
        score = 0

        questions_list = list(questions.keys())
        random.shuffle(questions_list)

        # -------- QUESTIONS LOOP --------
        for que_no, question in enumerate(questions_list, 1):
            print(f"Question {que_no}: {question}")

            options = questions[question]["options"]
            print_options(options)

            correct_ans = questions[question]["answer"]
            user_ans = input("Enter Your Answer : ")

            if check_answer(user_ans, options, correct_ans):
                print("Correct!")
                score += 1
            else:
                print(f"Wrong! Correct answer is: {options[int(correct_ans)-1]}")

        # -------- AFTER QUIZ --------
        print(f"\nYour Final Score is : {score} pts")

        play = input(f"{username} Do you want to play again? : ")
        sys_play = play.capitalize()

        if sys_play == "Yes":
            is_playing = True
        elif sys_play == "No":
            is_playing = False
            print("**********************************Thank You********************************************************")
        else:
            print("Pls Enter Yes/No")
            is_playing = False
    



    


        



 