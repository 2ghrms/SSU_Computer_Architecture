#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE 256
#define START_PC 1000

typedef struct {
    char mnemonic[10];
    int rd, rs1, rs2, imm;

} Instruction;

Instruction* createInst(const char* mnemonic, int rd, int rs1, int rs2, int imm) {
    Instruction *inst = (Instruction *)malloc(sizeof(Instruction));
    
    strncpy(inst->mnemonic, mnemonic, sizeof(inst->mnemonic) - 1);
    inst->mnemonic[sizeof(inst->mnemonic) - 1] = '\0'; // 안전하게 문자열 종료
    inst->rd=rd;
    inst->rs1=rs1;
    inst->rs2=rs2;
    inst->imm=imm;
    return inst;
}

void toUpperCase(char *str) {
    int i = 0;
    while (str[i] != '\0') {  // 문자열 끝까지 반복
        str[i] = toupper((unsigned char)str[i]);  // toupper로 변환
        i++;
    }
}

// 어셈블리어 명령어 encoder + binary int to string
char* encode_instruction(const Instruction *inst) {
    int binary_inst=0;
    //R-type
    if (strcasecmp(inst->mnemonic, "ADD") == 0) {
        binary_inst = (0b0110011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (inst->rd << 7) | (0b0000000 << 25) | (0b000 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SUB") == 0) {
        binary_inst = (0b0110011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (inst->rd << 7) | (0b0100000 << 25) | (0b000 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SLL") == 0) {
        binary_inst = (0b0110011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (inst->rd << 7) | (0b0000000 << 25) | (0b001 <<12);
    }
    if (strcasecmp(inst->mnemonic, "XOR") == 0) {
        binary_inst = (0b0110011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (inst->rd << 7) | (0b0000000 << 25) | (0b100 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SRL") == 0) {
        binary_inst = (0b0110011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (inst->rd << 7) | (0b0000000 << 25) | (0b101 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SRA") == 0) {
        binary_inst = (0b0110011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (inst->rd << 7) | (0b0100000 << 25) | (0b101 <<12);
    }
    if (strcasecmp(inst->mnemonic, "OR") == 0) {
        binary_inst = (0b0110011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (inst->rd << 7) | (0b0000000 << 25) | (0b110 <<12);
    }
    if (strcasecmp(inst->mnemonic, "AND") == 0) {
        binary_inst = (0b0110011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (inst->rd << 7) | (0b0000000 << 25) | (0b111 <<12);
    }

    //I-type
    if (strcasecmp(inst->mnemonic, "ADDI") == 0) {
        binary_inst = (0b0010011) | (inst->rs1 << 15) | (inst->imm << 20) | (inst->rd << 7) | (0b000 <<12);
    }
    if (strcasecmp(inst->mnemonic, "XORI") == 0) {
        binary_inst = (0b0010011) | (inst->rs1 << 15) | (inst->imm << 20) | (inst->rd << 7) | (0b100 <<12);
    }
    if (strcasecmp(inst->mnemonic, "ORI") == 0) {
        binary_inst = (0b0010011) | (inst->rs1 << 15) | (inst->imm << 20) | (inst->rd << 7) | (0b110 <<12);
    }
    if (strcasecmp(inst->mnemonic, "ANDI") == 0) {
        binary_inst = (0b0010011) | (inst->rs1 << 15) | (inst->imm << 20) | (inst->rd << 7) | (0b111 <<12);
    }
    // slli, srli, srai
    if (strcasecmp(inst->mnemonic, "SLLI") == 0) {
        binary_inst = (0b0010011) | (inst->rs1 << 15) | (inst->imm << 20) | (inst->rd << 7) | (0b000000 << 26) | (0b001 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SRLI") == 0) {
        binary_inst = (0b0010011) | (inst->rs1 << 15) | (inst->imm << 20) | (inst->rd << 7) | (0b000000 << 26) | (0b101 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SRAI") == 0) {
        binary_inst = (0b0010011) | (inst->rs1 << 15) | (inst->imm << 20) | (inst->rd << 7) | (0b010000 << 26) | (0b101 <<12);
    }
    //lw
    if (strcasecmp(inst->mnemonic, "LW") == 0) {
        binary_inst = (0b0000011) | (inst->rs1 << 15) | (inst->imm << 20) | (inst->rd << 7) | (0b010 <<12);
    }
    //jalr
    if (strcasecmp(inst->mnemonic, "JALR") == 0) {
        binary_inst = (0b1100111) | (inst->rs1 << 15) | (inst->imm << 20) | (inst->rd << 7) | (0b000 <<12);
    }

    //S-type
    if (strcasecmp(inst->mnemonic, "SW") == 0) {
        binary_inst = (0b0100011) | (inst->rs1 << 15) | (inst->rs2 << 20) | ((inst->imm&0b11111)<<7) | ((inst->imm>>5)<<25) |(0b010<<12);
    }

    //SB-type
    if (strcasecmp(inst->mnemonic, "BEQ") == 0) {
        binary_inst = (0b1100011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (((inst->imm>>10)&1)<<25) | ((inst->imm&0b1111)<<8) | (((inst->imm>>4)&0b11111)<<25) | (((inst->imm>>11)&1)<<31) | (0b000 <<12);
    }
    if (strcasecmp(inst->mnemonic, "BNE") == 0) {
        binary_inst = (0b1100011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (inst->rd << 7) | (((inst->imm>>10)&1)<<25) | ((inst->imm&0b1111)<<8) | (((inst->imm>>4)&0b11111)<<25) | (((inst->imm>>11)&1)<<31) | (0b001 <<12);
    }
    if (strcasecmp(inst->mnemonic, "BLT") == 0) {
        binary_inst = (0b1100011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (inst->rd << 7) | (((inst->imm>>10)&1)<<25) | ((inst->imm&0b1111)<<8) | (((inst->imm>>4)&0b11111)<<25) | (((inst->imm>>11)&1)<<31) | (0b100 <<12);
    }
    if (strcasecmp(inst->mnemonic, "BGE") == 0) {
        binary_inst = (0b1100011) | (inst->rs1 << 15) | (inst->rs2 << 20) | (inst->rd << 7) | (((inst->imm>>10)&1)<<25) | ((inst->imm&0b1111)<<8) | (((inst->imm>>4)&0b11111)<<25) | (((inst->imm>>11)&1)<<31) | (0b101 <<12);
    }

    //UJ-type
    if (strcasecmp(inst->mnemonic, "JAL") == 0) {
        binary_inst = (0b1101111) | (inst->rd << 7) | (((inst->imm>>11)&0b11111111)<<12) | (((inst->imm>>10)&1)<<20) | ((inst->imm&0b1111111111)<<21) | (((inst->imm>>19)&1)<<31);
    }

    //Exit
    if (strcasecmp(inst->mnemonic, "EXIT") == 0) {
        binary_inst = 0xFFFFFFFF; // 종료 명령
    }

    free(inst);
    char *buffer = malloc(33);
    if(binary_inst){
        for (int i = 31; i >= 0; i--) {
            buffer[31 - i] = (binary_inst & (1 << i)) ? '1' : '0';
        }
        buffer[32] = '\0';
        return buffer;
    }
}

void process_instruction(char *line, FILE *o_file, FILE *trace_file, int *pc, int *error_flag) {
    // Parse and encode instruction
    Instruction inst;
    char mnemonic[MAX_LINE];
    int rd, rs1, rs2, imm;
    if (sscanf(line, "%s x%d, x%d, x%d", mnemonic, &rd, &rs1, &rs2) == 4) {
        // R-type
        toUpperCase(mnemonic);
        char* machine_code = encode_instruction(createInst(mnemonic, rd, rs1, rs2, 0));
        fprintf(o_file, "%s\n", machine_code);
    } else if (sscanf(line, "%s x%d, x%d, %d", mnemonic, &rd, &rs1, &imm) == 4) {
        // I-type except lw & jalr
        toUpperCase(mnemonic);
        char* machine_code = encode_instruction(createInst(mnemonic, rd, rs1, 0, imm));
        fprintf(o_file, "%s\n", machine_code);
    } else if (sscanf(line, "%s x%d, %d(x%d)", mnemonic, &rd, &imm, &rs1) == 4) {
        toUpperCase(mnemonic);
        char* machine_code=NULL;
        if(strcasecmp(mnemonic, "SW") == 0){
        // S-type
        machine_code = encode_instruction(createInst(mnemonic, 0, rs1, rd, imm)); // rs2자리에 rd값을 넣어준다.
        } else {
        // I-type ; lw & jalr
        machine_code = encode_instruction(createInst(mnemonic, rd, rs1, 0, imm));
        }
        fprintf(o_file, "%s\n", machine_code);
    } else if (sscanf(line, "%s x%d, x%d, %d", mnemonic, &rs1, &rs2, &imm) == 4) {
        // SB-type
        toUpperCase(mnemonic);
        char* machine_code = encode_instruction(createInst(mnemonic, rd, rs1, rs2, imm));
        fprintf(o_file, "%s\n", machine_code);
    } else if (sscanf(line, "%s x%d, %d", mnemonic, &rd, &imm) == 3) {
        // UJ-type
        toUpperCase(mnemonic);
        char* machine_code = encode_instruction(createInst(mnemonic, rd, 0, 0, imm));
        fprintf(o_file, "%s\n", machine_code);
    } else if (sscanf(line, "%s", mnemonic) == 1) {
        char* machine_code = encode_instruction(createInst(mnemonic, 0, 0, 0, 0));
        fprintf(o_file, "%s\n", machine_code);
    } else {
        *error_flag = 1; // Syntax error
        return;
    }

    fprintf(trace_file, "%d\n", *pc);
    *pc += 4;
}

int main() {
    char input_file[MAX_LINE];
    while (1) {
        printf(">> Enter Input File Name: ");
        scanf("%s", input_file);

        if (strcmp(input_file, "terminate") == 0) break;

        FILE *input = fopen(input_file, "r");
        if (!input) {
            printf("Input file does not exist!!\n");
            continue;
        }

        char o_file_name[MAX_LINE], trace_file_name[MAX_LINE];
        snprintf(o_file_name, MAX_LINE, "%s.o", input_file);
        snprintf(trace_file_name, MAX_LINE, "%s.trace", input_file);

        FILE *o_file = fopen(o_file_name, "w");
        FILE *trace_file = fopen(trace_file_name, "w");

        int pc = START_PC;
        int error_flag = 0;
        int register_file[32]={1,2,3,4,5,6,0,};
        char line[MAX_LINE];

        while (fgets(line, MAX_LINE, input)) {
            if (strlen(line) <= 1) continue; // Ignore empty lines
            process_instruction(line, o_file, trace_file, &pc, &error_flag);
            if (error_flag) break;
        }

        fclose(input);
        fclose(o_file);
        fclose(trace_file);

        if (error_flag) {
            printf("Syntax Error!!\n");
            remove(o_file_name);
            remove(trace_file_name);
        }
    }
    return 0;
}

/*
// 명령어 파싱
int parse_instruction(const char *line, Instruction *inst) {
    char temp[MAX_LINE];
    strcpy(temp, line);
    char *token = strtok(temp, " ,()");

    if (token == NULL) return 0;
    strcpy(inst->mnemonic, token);
    inst->rd = inst->rs1 = inst->rs2 = inst->imm = -1;

    if (strcasecmp(token, "EXIT") == 0) return 1;

    token = strtok(NULL, " ,()");
    if (token) inst->rd = atoi(token + 1);
    token = strtok(NULL, " ,()");
    if (token) inst->rs1 = atoi(token + 1);
    token = strtok(NULL, " ,()");
    if (token && strchr(token, 'x')) inst->rs2 = atoi(token + 1);
    else if (token) inst->imm = atoi(token);

    return 1;
}

// 프로그램 실행 및 PC 추적
void execute_program(FILE *o_file, FILE *trace_file, Instruction *instructions, int count) {
    int pc = START_PC;
    for (int i = 0; i < count; i++) {
        fprintf(trace_file, "%d\\n", pc);
        unsigned int machine_code = encode_instruction(&instructions[i]);
        fprintf(o_file, "%08x\\n", machine_code);

        if (strcasecmp(instructions[i].mnemonic, "EXIT") == 0) break;
        pc += 4; // 다음 명령어
    }
}
*/