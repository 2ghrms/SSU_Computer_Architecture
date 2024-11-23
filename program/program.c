#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_FILE_NAME 100 // 파일 이름 최대 길이
#define MAX_INST_LEN 1000 // 명령어 최대 길이
#define MAX_INSTS 10000 // 명령어 최대 개수
#define MAX_LABEL_LEN 1000 // 레이블의 최대 길이 
#define MAX_LABELS 10000 // 레이블 최대 개수
#define START_PC 1000
#define R register_file

// pc와 에러 플래그, 레지스터 파일, 명령어 라인 읽기 위한 배열 선언
int pc;
int error_flag ;
int register_file[32];
char line[MAX_INST_LEN];

// RISC-V 명령어 구조체
typedef struct {
    char mnemonic[10];
    int rd, rs1, rs2, imm;
} Instruction;

// 레이블 구조체
typedef struct  {
    char name[MAX_LABEL_LEN];
    int address;
} Label;

// 레이블 주소와 이름 매핑 배열
Label label_table[MAX_LABELS]; // 레이블 이름 -> 주소(PC) 매핑
int label_count;

// 기능상 명령어 메모리 역할을 위한 구조체
typedef struct {
    int pc;
    long file_offset;
} InstMem;

// PC와 파일 오프셋 매핑 배열
InstMem pc_table[MAX_INSTS]; // PC -> 파일 오프셋 매핑
int instruction_count;

// 기능상 데이터 메모리 역할을 위한 구조체
typedef struct MemoryNode {
    uint32_t address;         // 메모리 주소
    int value;                // 저장된 값
    struct MemoryNode *next;  // 다음 노드
} DataMem;

// 명령어 생성 함수
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

// 명령어의 대소문자 구분을 하지 않기 위해서 모든 명령어는 대문자로 변환하여 입력에 들어가게 하기 위한 함수
void toUpperCase(char *str) {
    int i = 0;
    while (str[i] != '\0') {  // 문자열 끝까지 반복
        str[i] = toupper((unsigned char)str[i]);  // toupper로 변환
        i++;
    }
}

// PC에 따른 파일 오프셋, 레이블 저장을 위한 함수
void map_pc_to_offsets_and_labels(FILE *input) {
    pc = START_PC;

    // 현재 파일 오프셋을 저장할 변수
    long current_offset = 0;

    while (fgets(line, MAX_INST_LEN, input)) {
        // 현재 읽은 파일의 위치 저장
        current_offset = ftell(input) - strlen(line);

        // 문자열 좌우 공백 제거
        char *trimmed_line = line;
        while (isspace(*trimmed_line)) trimmed_line++; // 좌측 공백 제거
        char *end = trimmed_line + strlen(trimmed_line) - 1;
        while (end > trimmed_line && isspace(*end)) end--; // 우측 공백 제거
        *(end + 1) = '\0'; // 문자열 종료

        //printf("Read Line: '%s'\n", trimmed_line); // 읽은 라인 출력

        if (strlen(trimmed_line) == 0) {
            // 공백 라인은 무시
            //printf("Skipped: Empty Line\n");
            continue;
        }

        char *colon = strchr(trimmed_line, ':');
        if (colon) {
            // 레이블 처리
            *colon = '\0'; // 레이블 이름 끝을 '\0'으로 설정
            strncpy(label_table[label_count].name, trimmed_line, MAX_LABEL_LEN - 1);
            label_table[label_count].name[MAX_LABEL_LEN - 1] = '\0'; // 안전한 종료
            label_table[label_count].address = pc;

            //printf("Label Found: '%s', PC: %d\n", trimmed_line, pc); // 레이블 디버깅 출력
            label_count++;
        } else {
            // 명령어 처리
            pc_table[instruction_count].pc = pc;
            pc_table[instruction_count].file_offset = current_offset;

            //printf("Instruction Found: PC: %d, Offset: %ld\n", pc, current_offset); // 명령어 디버깅 출력
            instruction_count++;
            pc += 4; // PC 값 증가
        }
    }

    // PC와 파일 포인터를 다시 처음으로 이동
    pc=START_PC;
    rewind(input);
}


// PC -> 파일 오프셋 get 함수
long get_file_offset_from_pc(int target_pc) {
    for (int i = 0; i < instruction_count; i++) {
        if (pc_table[i].pc == target_pc) {
            return pc_table[i].file_offset;
        }
    }
    return -1; // PC에 해당하는 명령어(파일위치)가 없을 경우
}

// 레이블 이름 -> 주소(PC) get 함수
int get_address_from_label(const char *label) {
    for (int i = 0; i < label_count; i++) {
        if (strcasecmp(label_table[i].name, label) == 0) {
            return label_table[i].address;
        }
    }
    return -1; // 레이블이름에 해당하는 주소(PC)가 없는 경우; 레이블이 없는 경우
}

/*******데이터 메모리를 위한 해쉬형태의 메모리 정의********/

// 해시 테이블 크기와 해시테이블 선언
#define HASH_SIZE 1024
DataMem *data_table[HASH_SIZE];

// 해시 함수
uint32_t hash(uint32_t address) {
    return address % HASH_SIZE;
}

// 데이터 메모리 읽기 함수
int memory_read(uint32_t address) {
    uint32_t index = hash(address);
    DataMem *node = data_table[index];
    while (node) {
        if (node->address == address) {
            return node->value; // 해당 주소의 값 반환
        }
        node = node->next;
    }
    return 0; // 메모리에 값이 없으면 기본값 반환
}

// 데이터 메모리 쓰기 함수
void memory_write(uint32_t address, int value) {
    uint32_t index = hash(address);
    DataMem *node = data_table[index];

    // 기존 노드 업데이트
    while (node) {
        if (node->address == address) {
            node->value = value;
            return;
        }
        node = node->next;
    }

    // 새 노드 추가
    node = (DataMem *)malloc(sizeof(DataMem));
    node->address = address;
    node->value = value;
    node->next = data_table[index];
    data_table[index] = node;
}

// 데이터 메모리 해제 함수
void memory_free() {
    for (int i = 0; i < HASH_SIZE; i++) {
        DataMem *node = data_table[i];
        while (node) {
            DataMem *temp = node;
            node = node->next;
            free(temp);
        }
        data_table[i] = NULL;
    }
}

// 어셈블리어 명령어 인코더 -> binary값을 int에서 string으로 변환해주는 함수
char* encode_instruction(Instruction *inst) {
    int binary_inst=0;
    int rd=inst->rd, rs1=inst->rs1, rs2=inst->rs2, imm=inst->imm;
    //R-type
    if (strcasecmp(inst->mnemonic, "ADD") == 0) {
        binary_inst = (0b0110011) | (rs1 << 15) | (rs2 << 20) | (rd << 7) | (0b0000000 << 25) | (0b000 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SUB") == 0) {
        binary_inst = (0b0110011) | (rs1 << 15) | (rs2 << 20) | (rd << 7) | (0b0100000 << 25) | (0b000 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SLL") == 0) {
        binary_inst = (0b0110011) | (rs1 << 15) | (rs2 << 20) | (rd << 7) | (0b0000000 << 25) | (0b001 <<12);
    }
    if (strcasecmp(inst->mnemonic, "XOR") == 0) {
        binary_inst = (0b0110011) | (rs1 << 15) | (rs2 << 20) | (rd << 7) | (0b0000000 << 25) | (0b100 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SRL") == 0) {
        binary_inst = (0b0110011) | (rs1 << 15) | (rs2 << 20) | (rd << 7) | (0b0000000 << 25) | (0b101 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SRA") == 0) {
        binary_inst = (0b0110011) | (rs1 << 15) | (rs2 << 20) | (rd << 7) | (0b0100000 << 25) | (0b101 <<12);
    }
    if (strcasecmp(inst->mnemonic, "OR") == 0) {
        binary_inst = (0b0110011) | (rs1 << 15) | (rs2 << 20) | (rd << 7) | (0b0000000 << 25) | (0b110 <<12);
    }
    if (strcasecmp(inst->mnemonic, "AND") == 0) {
        binary_inst = (0b0110011) | (rs1 << 15) | (rs2 << 20) | (rd << 7) | (0b0000000 << 25) | (0b111 <<12);
    }
    //I-type
    if (strcasecmp(inst->mnemonic, "ADDI") == 0) {
        binary_inst = (0b0010011) | (rs1 << 15) | (imm << 20) | (rd << 7) | (0b000 <<12);
    }
    if (strcasecmp(inst->mnemonic, "XORI") == 0) {
        binary_inst = (0b0010011) | (rs1 << 15) | (imm << 20) | (rd << 7) | (0b100 <<12);
    }
    if (strcasecmp(inst->mnemonic, "ORI") == 0) {
        binary_inst = (0b0010011) | (rs1 << 15) | (imm << 20) | (rd << 7) | (0b110 <<12);
    }
    if (strcasecmp(inst->mnemonic, "ANDI") == 0) {
        binary_inst = (0b0010011) | (rs1 << 15) | (imm << 20) | (rd << 7) | (0b111 <<12);
    }
    // slli, srli, srai
    if (strcasecmp(inst->mnemonic, "SLLI") == 0) {
        binary_inst = (0b0010011) | (rs1 << 15) | (imm << 20) | (rd << 7) | (0b000000 << 26) | (0b001 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SRLI") == 0) {
        binary_inst = (0b0010011) | (rs1 << 15) | (imm << 20) | (rd << 7) | (0b000000 << 26) | (0b101 <<12);
    }
    if (strcasecmp(inst->mnemonic, "SRAI") == 0) {
        binary_inst = (0b0010011) | (rs1 << 15) | (imm << 20) | (rd << 7) | (0b010000 << 26) | (0b101 <<12);
    }
    //lw
    if (strcasecmp(inst->mnemonic, "LW") == 0) {
        binary_inst = (0b0000011) | (rs1 << 15) | (imm << 20) | (rd << 7) | (0b010 <<12);
    }
    //jalr
    if (strcasecmp(inst->mnemonic, "JALR") == 0) {
        binary_inst = (0b1100111) | (rs1 << 15) | (imm << 20) | (rd << 7) | (0b000 <<12);
    }
    //S-type : sw
    if (strcasecmp(inst->mnemonic, "SW") == 0) {
        binary_inst = (0b0100011) | (rs1 << 15) | (rs2 << 20) | ((imm&0b11111)<<7) | ((imm>>5)<<25) |(0b010<<12);
    }
    //SB-type
    if (strcasecmp(inst->mnemonic, "BEQ") == 0) {
        binary_inst = (0b1100011) | (rs1 << 15) | (rs2 << 20) | (((imm>>10)&1)<<7) | ((imm&0b1111)<<8) | (((imm>>4)&0b111111)<<25) | (((imm>>11)&1)<<31) | (0b000 <<12);
    }
    if (strcasecmp(inst->mnemonic, "BNE") == 0) {
        binary_inst = (0b1100011) | (rs1 << 15) | (rs2 << 20) | (((imm>>10)&1)<<7) | ((imm&0b1111)<<8) | (((imm>>4)&0b111111)<<25) | (((imm>>11)&1)<<31) | (0b001 <<12);
    } 
    if (strcasecmp(inst->mnemonic, "BLT") == 0) {
        binary_inst = (0b1100011) | (rs1 << 15) | (rs2 << 20) | (((imm>>10)&1)<<7) | ((imm&0b1111)<<8) | (((imm>>4)&0b111111)<<25) | (((imm>>11)&1)<<31) | (0b100 <<12);
    }
    if (strcasecmp(inst->mnemonic, "BGE") == 0) {
        imm=imm>>1;
        binary_inst = (0b1100011) | (rs1 << 15) | (rs2 << 20) | (((imm>>10)&1)<<7) | ((imm&0b1111)<<8) | (((imm>>4)&0b111111)<<25) | (((imm>>11)&1)<<31) | (0b101 <<12);
    }
    //UJ-type : jal
    if (strcasecmp(inst->mnemonic, "JAL") == 0) {
        binary_inst = (0b1101111) | (rd << 7) | (((imm>>11)&0b11111111)<<12) | (((inst->imm>>10)&1)<<20) | ((imm&0b1111111111)<<21) | (((imm>>19)&1)<<31);
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

// 명령어를 해석한다.
void instruction_encoder(FILE *input, FILE *o_file) {
    while(1){
        long offset = get_file_offset_from_pc(pc);
        if (offset == -1) {break;} // 해당 PC에 명령어가 없으면 종료

        fseek(input, offset, SEEK_SET); // 파일 위치 이동
        fgets(line, MAX_INSTS, input);  // 명령어 읽기

        //printf("inst : %s",line);
        //printf("pc : %d\n",pc);

        Instruction inst;
        int rd, rs1, rs2, imm;
        char mnemonic[MAX_INST_LEN];
        char label[MAX_LABEL_LEN];
        char* machine_code;

        if (sscanf(line, "%s x%d, x%d, x%d", mnemonic, &rd, &rs1, &rs2) == 4) {
            // R-type
            toUpperCase(mnemonic);
            machine_code = encode_instruction(createInst(mnemonic, rd, rs1, rs2, 0));
            fprintf(o_file, "%s\n", machine_code);
        } else if (sscanf(line, "%s x%d, x%d, %d", mnemonic, &rd, &rs1, &imm) == 4) {
            // I-type except lw & jalr
            toUpperCase(mnemonic);
            machine_code = encode_instruction(createInst(mnemonic, rd, rs1, 0, imm));
            fprintf(o_file, "%s\n", machine_code);
        } else if (sscanf(line, "%s x%d, %d(x%d)", mnemonic, &rd, &imm, &rs1) == 4) {
            toUpperCase(mnemonic);
            // S-type
            if(strcasecmp(mnemonic, "SW") == 0){ //sw
                machine_code = encode_instruction(createInst(mnemonic, 0, rs1, rd, imm)); // rs2자리에 rd값을 넣어준다.
            }
            // I-type 
            else { //lw&jalr
                machine_code = encode_instruction(createInst(mnemonic, rd, rs1, 0, imm));
            }
            fprintf(o_file, "%s\n", machine_code);
        } else if (sscanf(line, "%s x%d, x%d, %s", mnemonic, &rs1, &rs2, label) == 4) {
            // SB-type
            toUpperCase(mnemonic);
            int target_address = get_address_from_label(label);
            imm = target_address - pc;
            machine_code = encode_instruction(createInst(mnemonic, rd, rs1, rs2, imm));
            fprintf(o_file, "%s\n", machine_code);
        } else if (sscanf(line, "%s x%d, %s", mnemonic, &rd, label) == 3) {
            // UJ-type ; JAL
            toUpperCase(mnemonic);
            int target_address = get_address_from_label(label);
            imm = (target_address -pc)>>1;
            machine_code = encode_instruction(createInst(mnemonic, rd, 0, 0, imm));
            fprintf(o_file, "%s\n", machine_code);
        } else if (sscanf(line, "%s", mnemonic) == 1) {
            char* machine_code = encode_instruction(createInst(mnemonic, 0, 0, 0, 0));
            fprintf(o_file, "%s\n", machine_code);
        } else {
            error_flag = 1; // Syntax error
            return;
        }

        pc += 4;
        if(error_flag)
            break;
    }
    pc=START_PC;
    rewind(input);
}

void process_instruction(Instruction *inst) {
    int rd=inst->rd, rs1=inst->rs1, rs2=inst->rs2, imm=inst->imm;
    //R-type
    if (strcasecmp(inst->mnemonic, "ADD") == 0) {
        R[rd]=R[rs1]+R[rs2];
    }
    if (strcasecmp(inst->mnemonic, "SUB") == 0) {
        R[rd]=R[rs1]-R[rs2];
    }
    if (strcasecmp(inst->mnemonic, "SLL") == 0) {
        R[rd]=R[rs1]<<R[rs2];
    }
    if (strcasecmp(inst->mnemonic, "XOR") == 0) {
        R[rd]=R[rs1]^R[rs2];
    }
    if (strcasecmp(inst->mnemonic, "SRL") == 0) {
        R[rd]=(unsigned int)R[rs1]>>R[rs2];
    }
    if (strcasecmp(inst->mnemonic, "SRA") == 0) {
        R[rd]=R[rs1]>>R[rs2];
    }
    if (strcasecmp(inst->mnemonic, "OR") == 0) {
        R[rd]=R[rs1]|R[rs2];
    }
    if (strcasecmp(inst->mnemonic, "AND") == 0) {
        R[rd]=R[rs1]&R[rs2];
    }
    //I-type
    if (strcasecmp(inst->mnemonic, "ADDI") == 0) {
        R[rd]=R[rs1]+imm;
    }
    if (strcasecmp(inst->mnemonic, "XORI") == 0) {
        R[rd]=R[rs1]^imm;
    }
    if (strcasecmp(inst->mnemonic, "ORI") == 0) {
        R[rd]=R[rs1]|imm;
    }
    if (strcasecmp(inst->mnemonic, "ANDI") == 0) {
        R[rd]=R[rs1]&imm;
    }
    // slli, srli, srai
    if (strcasecmp(inst->mnemonic, "SLLI") == 0) {
        R[rd]=R[rs1]>>imm;
    }
    if (strcasecmp(inst->mnemonic, "SRLI") == 0) {
        R[rd]=(unsigned int)R[rs1]<<imm;
    }
    if (strcasecmp(inst->mnemonic, "SRAI") == 0) {
        R[rd]=R[rs1]<<imm;
    }
    //lw
    if (strcasecmp(inst->mnemonic, "LW") == 0) {
        uint32_t address = R[rs1] + imm; // 메모리 주소 계산
        R[rd] = memory_read(address);         // 메모리에서 값 읽기
    }
    //jalr
    if (strcasecmp(inst->mnemonic, "JALR") == 0) {
        R[rd] = pc+4;
        pc = (R[rs1] + (imm<<1))&(~1);
    }
    //S-type : sw
    if (strcasecmp(inst->mnemonic, "SW") == 0) {
        uint32_t address = R[rs1] + imm; // 메모리 주소 계산
        memory_write(address, R[rs2]);         // 메모리에 값 저장
    }
    //SB-type
    if (strcasecmp(inst->mnemonic, "BEQ") == 0) {
        if(R[rs1]==R[rs2]){
            pc = pc + (imm<<1);
        }
        else{
            pc = pc + 4;
        }
    }
    if (strcasecmp(inst->mnemonic, "BNE") == 0) {
        if(R[rs1]!=R[rs2]){
            pc = pc + (imm<<1);
        }
        else{
            pc = pc + 4;
        }
    } 
    if (strcasecmp(inst->mnemonic, "BLT") == 0) {
        if(R[rs1]<R[rs2]){
            pc = pc + (imm<<1);
        }
        else{
            pc = pc + 4;
        }
    }
    if (strcasecmp(inst->mnemonic, "BGE") == 0) {
        if(R[rs1]>=R[rs2]){
            pc = pc + (imm<<1);
        }
        else{
            pc = pc + 4;
        }
    }
    //UJ-type : jal
    if (strcasecmp(inst->mnemonic, "JAL") == 0) {
        R[rd] = pc + 4;
        pc = pc + (imm<<1);
    }
}

//명령어를 진행시켜서 .trace 파일 작성
void instruction_processor(FILE *input, FILE *trace_file) {
    while(1){
        long offset = get_file_offset_from_pc(pc);
        if (offset == -1) {break;} // 해당 PC에 명령어가 없으면 종료

        fseek(input, offset, SEEK_SET); // 파일 위치 이동
        fgets(line, MAX_INSTS, input);  // 명령어 읽기
        fprintf(trace_file, "%d\n", pc); // 현재 PC 기록

        printf("inst : %s",line);
        printf("pc : %d\n",pc);

        Instruction inst;
        int rd, rs1, rs2, imm;
        char mnemonic[MAX_INST_LEN];
        char label[MAX_LABEL_LEN];
        int pc_count=1;
        char* machine_code;

        if (sscanf(line, "%s x%d, x%d, x%d", mnemonic, &rd, &rs1, &rs2) == 4) {
            // R-type
            toUpperCase(mnemonic);
            process_instruction(createInst(mnemonic, rd, rs1, rs2, 0));
        } else if (sscanf(line, "%s x%d, x%d, %d", mnemonic, &rd, &rs1, &imm) == 4) {
            // I-type except lw & jalr
            toUpperCase(mnemonic);
            process_instruction(createInst(mnemonic, rd, rs1, 0, imm));
        } else if (sscanf(line, "%s x%d, %d(x%d)", mnemonic, &rd, &imm, &rs1) == 4) {
            toUpperCase(mnemonic);
            // S-type
            if(strcasecmp(mnemonic, "SW") == 0){ //sw
                process_instruction(createInst(mnemonic, 0, rs1, rd, imm)); // rs2자리에 rd값을 넣어준다.
            }
            // I-type 
            else if(strcasecmp(mnemonic, "JALR") == 0){ //jalr
                process_instruction(createInst(mnemonic, rd, rs1, 0, imm));
                pc_count=0;
            }
            else { //lw
                process_instruction(createInst(mnemonic, rd, rs1, 0, imm));  
            }
        } else if (sscanf(line, "%s x%d, x%d, %s", mnemonic, &rs1, &rs2, label) == 4) {
            // SB-type
            toUpperCase(mnemonic);
            int target_address = get_address_from_label(label);
            if (target_address == -1) {
                error_flag = 1; // 레이블이 존재하지 않음
                return;
            }
            imm = (target_address - pc)>>1;
            pc_count=0;
            process_instruction(createInst(mnemonic, rd, rs1, rs2, imm));
        } else if (sscanf(line, "%s x%d, %s", mnemonic, &rd, label) == 3) {
            // UJ-type ; JAL
            toUpperCase(mnemonic);
            int target_address = get_address_from_label(label);
            if (target_address == -1) {
                error_flag = 1; // 레이블이 존재하지 않음
                return;
            }
            imm = (target_address -pc)>>1;
            pc_count=0;
            process_instruction(createInst(mnemonic, rd, 0, 0, imm));
        } else if (sscanf(line, "%s", mnemonic) == 1&&strcasecmp(mnemonic, "EXIT") == 0) {
            break;
        } else {
            error_flag = 1; // Syntax error
            return;
        }

        if(pc_count)
            pc += 4;
    }
    pc=START_PC;
    rewind(input);
}

int main() {
    char input_file[MAX_FILE_NAME];
    while (1) {
        printf(">> Enter Input File Name: ");
        scanf("%s", input_file);

        if (strcmp(input_file, "terminate") == 0) break;

        FILE *input = fopen(input_file, "r");
        if (!input) {
            printf("Input file does not exist!!\n");
            continue;
        }

        char input_base_name[MAX_FILE_NAME];
        strncpy(input_base_name, input_file, MAX_FILE_NAME);
        char *dot = strrchr(input_base_name, '.');
        if(dot) *dot = '\0';

        char o_file_name[MAX_FILE_NAME], trace_file_name[MAX_FILE_NAME];
        snprintf(o_file_name, MAX_FILE_NAME, "%s.o", input_base_name);
        snprintf(trace_file_name, MAX_FILE_NAME, "%s.trace", input_base_name);

        FILE *o_file = fopen(o_file_name, "w");
        FILE *trace_file = fopen(trace_file_name, "w");

        //전역변수 초기화
        pc = START_PC;
        error_flag = 0;
        memset(register_file, 0, sizeof(register_file));
        for (int i = 0; i <= 6; i++) {
            register_file[i] = i ; // 레지스터 초기값 설정
        }
        memset(line, 0, sizeof(line));
        memset(label_table, 0, sizeof(label_table));
        label_count = 0;
        memset(pc_table, 0, sizeof(pc_table));
        instruction_count=0;
        memset(data_table, 0, sizeof(data_table));

        // 명령어와 레이블을 먼저 PC에 매핑해줌
        map_pc_to_offsets_and_labels(input);

        // 입력파일의 명령어를 32bit 기계어 코드로 변환해주는 함수
        instruction_encoder(input, o_file);

        // 입력파일의 명령어를 처리해주는 부분
        instruction_processor(input, trace_file);
        
        // 데이터 메모리 해제
        memory_free();

        fclose(input);
        fclose(o_file);
        fclose(trace_file);

        // error_flag를 통해 에러 발생 시 출력 파일 삭제하도록 함
        if (error_flag) {
            printf("Syntax Error!!\n");
            remove(o_file_name);
            remove(trace_file_name);
        }
    }
    return 0;
}