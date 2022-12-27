#include <stdio.h>
#include <stdlib.h>

int flag_price = 420;
unsigned int balance = 100;

void menu_options(){
    puts("\nOptions:");
    puts("1. Buy flag");
    puts("2. Exit\n");
    return;
}

void purchase(){
    unsigned int quantity;
    unsigned int pay_price;
    FILE* ptr;
    char c;
    puts("How many flags do you want to purchase?");
    scanf("%u",&quantity);
    if (quantity < 1) {
        puts("Here are your imaginary flags:");
        return;
    }
    pay_price = flag_price * quantity;
    if (pay_price <= balance) {
        balance -= pay_price;
        if (quantity > 1) {
            puts("You don't have to flex how rich you are...");
        }
        ptr = fopen("flag.txt","r");

        if (ptr == NULL) {
            puts("Missing file?");
        }
        c = fgetc(ptr);
        while (c != EOF) {
            printf("%c",c);
            c = fgetc(ptr);
        }
        fclose(ptr);
    } else {
        puts("You do not have enough money!");
    }
    return;
}

int main(){
    unsigned int user_input;
    puts("Welcome to my flag shop!\nBuy anything from flags, to flags!");
    while (1){
        menu_options();
        printf("<<< ");
        scanf("%u",&user_input);
        if (user_input == 1){
            purchase();
        } else {
            printf("Come again!");
            exit(0);
        }
    }
   return 0;
}
