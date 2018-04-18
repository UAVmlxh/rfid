#include <stdio.h>
#include "RFID.h"
#include <bcm2835.h>
#include <stdlib.h>
#include <string.h>

unsigned char randnum[16]={};
// RFID 初始化
void MFRC522_Initializtion()
{
	bcm2835_aux_spi_begin();
	//bcm2835_spi_begin();
	bcm2835_spi_setBitOrder(BCM2835_SPI_BIT_ORDER_MSBFIRST); 
	//MSB first
	bcm2835_spi_setDataMode(BCM2835_SPI_MODE0);
	//SPI Data
	
	bcm2835_aux_spi_setClockDivider(BCM2835_SPI_CLOCK_DIVIDER_2048);
	//bcm2835_spi_setClockDivider(BCM2835_SPI_CLOCK_DIVIDER_65536);
	
	bcm2835_spi_chipSelect(BCM2835_SPI_CS2);
	bcm2835_spi_setChipSelectPolarity(BCM2835_SPI_CS2, LOW);
	
	WriteRawRC(CommandReg, PCD_RESETPHASE);
	WriteRawRC(TModeReg,0x8D);
	WriteRawRC(TPrescalerReg,0x3E);
	WriteRawRC(TReloadRegL, 30);
	WriteRawRC(TReloadRegH, 0);
	WriteRawRC(TxAutoReg, 0x40);
	WriteRawRC(ModeReg, 0x3D);
	AntennaOn();
}
/**********************************************
功能:  卡片进入休眠模式
返回:  成功放回MI_OK
***********************************************/
char PcdHalt(void)
{
	char status;
	unsigned char unLen;
	unsigned char buff[4];
	buff[0] = PICC_HALT;
	buff[1] = 0;
	CalulateCRC(buff, 2, &buff[2]);
	status = PcdComMF522(PCD_TRANSCEIVE, buff, 4, buff, &unLen);
	return MI_OK;
}
//开天线   
void AntennaOn(void)
{
	unsigned char temp;
	temp = ReadRawRC(TxControlReg);
	if(!(temp & 0x03))
	{
		setBitMask(TxControlReg, 0x03);
	}
}
//关闭天线
void AntennaOff(void)
{
	unsigned char temp;
	temp = ReadRawRC(TxControlReg);
	if(!(temp & 0x03))
	{
		ClearBitMask(TxControlReg, 0x03);
	}
}
//写寄存器
void WriteRawRC(unsigned char Address, unsigned char value)
{
    unsigned char buff[2];
    buff[0] = (char)((Address<<1)&0x7E);
    buff[1] = (char)value;
    
    bcm2835_aux_spi_transfern(buff,2); 
}
//SPI通信 发送地址 返回得到的字节
unsigned char ReadRawRC(unsigned char Address)
{
    unsigned char buff[2];
    buff[0] = ((Address<<1)&0x7E)|0x80;
	bcm2835_aux_spi_transfern(buff,2);
    return (unsigned char)buff[1];
}
/********************************************************
功能： 寻卡
		reqMode：寻卡方式
			0x52 = 寻感应区域内所有符合14443A标准卡
			0x26 = 寻卡进入休眠状态的卡
	   *TagType：卡片类型
			0x4400 = Mifare_UltraLight
			0x0400 = Mifare_One(S50)
			0x0200 = Mifare_One(S70)
			0x0800 = Mifare_Pro(X)
			0x4403 = Mifare_DESFire
	返回: 成功放回MI_OK
**********************************************************/
char PcdRequest(unsigned char reqMode, unsigned char *TagType)
{
    char status;
	unsigned char backBits;
	WriteRawRC(BitFramingReg, 0x07);
	TagType[0] = reqMode;
	status = PcdComMF522(PCD_TRANSCEIVE, TagType, 1, TagType, &backBits);
	if((status != MI_OK) || (backBits != 0x10))
		status = MI_ERR;
	return status;
}
void setBitMask(unsigned char reg, unsigned char mask)
{
	unsigned char tmp;
	tmp = ReadRawRC(reg);
	WriteRawRC(reg, tmp | mask);   //set bit mask
}
void ClearBitMask(unsigned char reg, unsigned char mask)
{
	unsigned char tmp;
	tmp = ReadRawRC(reg);
	WriteRawRC(reg, tmp & (~mask));
}

/////////////////////////////////////////////////////////////////////
//功    能：读取M1卡一块数据 （经过密码检验后才能读取数据）
//参数说明: addr[IN]：块地址
//          pData[OUT]：读出的数据，16字节
//返    回: 成功返回MI_OK
///////////////////////////////////////////////////////////////////// 
char PcdRead(unsigned char addr,unsigned char *pData)
{
    char status;
    unsigned char  unLen;
    unsigned char i,ucComMF522Buf[MAX_LEN]; 

    ucComMF522Buf[0] = PICC_READ;
    ucComMF522Buf[1] = addr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
   
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);
	
    if ((status == MI_OK) && (unLen == 0x90))
 //   {   memcpy(pData, ucComMF522Buf, 16);   }
    {
        for (i=0; i<16; i++)
        {    *(pData+i) = ucComMF522Buf[i];   }
    }
    else
    {   status = MI_ERR;   }
    
    return status;
}
/////////////////////////////////////////////////////////////////////
//功    能：写数据到M1卡一块 （经过密码检验后才能写入数据）
//参数说明: addr[IN]：块地址
//          pData[IN]：写入的数据，16字节
//返    回: 成功返回MI_OK
/////////////////////////////////////////////////////////////////////                  
char PcdWrite(unsigned char addr,unsigned char *pData)
{
    char status;
    unsigned char  unLen;
    unsigned char i,ucComMF522Buf[MAX_LEN]; 
    
    ucComMF522Buf[0] = PICC_WRITE;
    ucComMF522Buf[1] = addr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
 
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

    if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
    {   status = MI_ERR;   }
        
    if (status == MI_OK)
    {
        //memcpy(ucComMF522Buf, pData, 16);
        for (i=0; i<16; i++)
        {    ucComMF522Buf[i] = *(pData+i);   }
        CalulateCRC(ucComMF522Buf,16,&ucComMF522Buf[16]);

        status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,18,ucComMF522Buf,&unLen);
        if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
        {   status = MI_ERR;   }
    }
    
    return status;
}

/////////////////////////////////////////////////////////////////////
//功    能：验证卡片密码
//参数说明: auth_mode[IN]: 密码验证模式
//                 0x60 = 验证A密钥
//                 0x61 = 验证B密钥 
//          addr[IN]：块地址
//          pKey[IN]：密码
//          pSnr[IN]：卡片序列号，4字节
//返    回: 成功返回MI_OK
/////////////////////////////////////////////////////////////////////               
char PcdAuthState(unsigned char auth_mode,unsigned char addr,unsigned char *pKey,unsigned char *pSnr)
{
    char status;
    unsigned char unLen;
    unsigned char i,ucComMF522Buf[MAX_LEN]; 

    ucComMF522Buf[0] = auth_mode;
    ucComMF522Buf[1] = addr;
    for (i=0; i<6; i++)
    {    ucComMF522Buf[i+2] = *(pKey+i);   }
    for (i=0; i<6; i++)
    {    ucComMF522Buf[i+8] = *(pSnr+i);   }
 //   memcpy(&ucComMF522Buf[2], pKey, 6); 
 //   memcpy(&ucComMF522Buf[8], pSnr, 4); 
    
    status = PcdComMF522(PCD_AUTHENT,ucComMF522Buf,12,ucComMF522Buf,&unLen);
    if ((status != MI_OK) || (!(ReadRawRC(Status2Reg) & 0x08)))
    {   status = MI_ERR;   }
    
    return status;
}
/*********************************************************************************
功能：通过RC522和IC卡通信
参数说明：	command  :RC522命令字
		   *sendData :通过RC522发送到卡片的数据
			sendLen  :发送数据的字节长度
			backData :接受到的卡片返回数据
		   *backLen  :返回数据的位长度

**********************************************************************************/
char PcdComMF522(unsigned char command, unsigned char *sendData, unsigned char sendLen, unsigned char *backData, unsigned char *backLen)
{
	char status = MI_ERR;
	unsigned char irqEn = 0x00;
	unsigned char waitIRq = 0x00;
	unsigned char lastBits;
	unsigned char n;
	unsigned int i;
	switch(command)
	{
		case PCD_AUTHENT:     //认证卡密
		{
			irqEn = 0x12;
			waitIRq = 0x10;
			break;
		}
		case PCD_TRANSCEIVE:  //发送FIFO中数据
		{
			irqEn = 0x77;
			waitIRq = 0x30;
			break;
		}
		default:
			break;
  }
	WriteRawRC(ComIEnReg, irqEn|0x80); //允许中断请求
	ClearBitMask(ComIrqReg, 0x80);       //清除所有中断请求位
	WriteRawRC(CommandReg, PCD_IDLE);   //无动作，取消当前命令
	setBitMask(FIFOLevelReg, 0x80);       //FlushBuffer=1, FIFO初始化
	//向FIFO中写入数据
	for (i=0; i<sendLen;i++)
	{
		WriteRawRC(FIFODataReg, sendData[i]);
	}
	//执行命令
	WriteRawRC(CommandReg, command);
	if(command == PCD_TRANSCEIVE)
    setBitMask(BitFramingReg, 0x80);
	//等待接收数据完成
	i = 2000; //i根据时钟频率调整，操作M1卡最大等待时间25ms
	do
	{
		n = ReadRawRC(ComIrqReg);
		i--;
	}
	while ((i!=0) && !(n&0x01) && !(n&waitIRq));
	ClearBitMask(BitFramingReg, 0x80);
	if(i != 0)
	{
		if(!(ReadRawRC(ErrorReg) & 0x1B))
		{
			status = MI_OK;
			if(n & irqEn & 0x01)
				status = MI_NOTAGERR;
			if(command == PCD_TRANSCEIVE)
			{
				n = ReadRawRC(FIFOLevelReg);
				lastBits = ReadRawRC(ControlReg) & 0x07;
				if(lastBits)
					*backLen = (n-1)*8 + lastBits;
				else
					*backLen = n*8;
				if(n == 0)
					n = 1;
				if(n > MAX_LEN)
					n = MAX_LEN;
				//读取FIFO中接收到的数据
				for (i=0; i<n;i++)
					backData[i] = ReadRawRC(FIFODataReg);
			}
		}
		else
			status = MI_ERR;
	}
	//setBitMask(ControlReg,0x80);
	//WriteRawRC(CommandReg,PCD_IDLE);
	return status;
}

/***********************************************
用MF522计算  CRC16  函数
***********************************************/
void CalulateCRC(unsigned char *pIndata, unsigned char len, unsigned char *pOutData)
{
	unsigned char i, n;
	ClearBitMask(DivIrqReg, 0x04);
	setBitMask(FIFOLevelReg, 0x80);
	for (i=0; i<len;i++)
	{
		WriteRawRC(FIFODataReg, *(pIndata+i));
	}
	WriteRawRC(CommandReg, PCD_CALCCRC);//	CRC计算
	i = 0xFF;
	do
	{
		n = ReadRawRC(DivIrqReg);   //	包含中断请求标志
		i--;
	}
	while ((i!=0) && !(n&0x04));
	pOutData[0] = ReadRawRC(CRCResultRegL); //显示计算CRC计算后的低位
	pOutData[1] = ReadRawRC(CRCResultRegM); //显示计算CRC计算后的高位
}

/////////////////////////////////////////////////////////////////////
//功    能：选定卡片
//参数说明: pSnr[IN]:卡片序列号，4字节
//返    回: 成功返回MI_OK
/////////////////////////////////////////////////////////////////////
char PcdSelect(unsigned char *pSnr)
{
    char status;
    unsigned char i;
    unsigned char  unLen;
    unsigned char ucComMF522Buf[MAX_LEN]; 
    
    ucComMF522Buf[0] = PICC_ANTICOLL1;
    ucComMF522Buf[1] = 0x70;
    ucComMF522Buf[6] = 0;
    for (i=0; i<4; i++)
    {
    	ucComMF522Buf[i+2] = *(pSnr+i);
    	ucComMF522Buf[6]  ^= *(pSnr+i);
    }
    CalulateCRC(ucComMF522Buf,7,&ucComMF522Buf[7]);
  
    ClearBitMask(Status2Reg,0x08);

    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,9,ucComMF522Buf,&unLen);
    
    if ((status == MI_OK) && (unLen == 0x18))
    {   status = MI_OK;  }
    else
    {   status = MI_ERR;    }

    return status;
}
/************************************************
功能: 防冲撞
参数说明: serNum[IN]:卡片序列号，4字节
返回: 成功返回MI_OK
**************************************************/
char PcdAnticoll(unsigned char *serNum)
{
	char status;
	unsigned char i;
	unsigned char serNumCheck=0;
	unsigned char unLen;
	
	ClearBitMask(Status2Reg, 0x08);
	WriteRawRC(BitFramingReg, 0x00);
	ClearBitMask(CollReg,0x80);
	
	serNum[0] = PICC_ANTICOLL;
	serNum[1] = 0x20;
	
	status = PcdComMF522(PCD_TRANSCEIVE, serNum, 2, serNum, &unLen);
	if(status == MI_OK)
	{
		//校验卡序列号
		for (i=0; i<4; i++)
		{
			*(serNum+i)  = serNum[i];
			serNumCheck ^= serNum[i];
		}
		if(serNumCheck != serNum[i])
		{
			status = MI_ERR;
		}
	}
	setBitMask(CollReg, 0x80);
	return status;
}





/***********************************************
功能：读取某一个块的数据  
返回：16个字节的数组
参数说明： adress
		  *key
		  *iNum
**********************************************/
char readMess(unsigned char adress,unsigned char *key,unsigned char *iNum)
{
	unsigned char s;//读出2个字节数据TagType--卡片类型代码
	char status;
	unsigned char card_num[4];   		//IC卡的卡号
	unsigned char i;
	
	status=PcdRequest(0x52,&s);    //搜索卡片类型
	status=PcdAnticoll(card_num);  //读卡号
	status=PcdSelect(card_num);    //选卡
	if(status ==MI_OK)
	{
	//验证卡片密码
	// PICC_AUTHENT1A  验证A密钥
	// PICC_AUTHENT1B  验证B密钥
	status=PcdAuthState(PICC_AUTHENT1A,adress,key,card_num);
	memset(iNum,0,16);  //清空数组数据
	status=PcdRead(adress,iNum);
		if(status == MI_OK)
		{
			printf("read data sucess!!\n");
		}
		for(i=0;i<16;i++)
			{
				printf(" %x ",iNum[i]);
			}
				printf("\n");
	}
	
	PcdHalt();
	sleep(1.5);
	return status;
}

/***********************************************
功能：写入某一个块的数据  
返回：16个字节的数组
参数说明： adress
		  *key
		  *iNum
***********************************************/
char writeMess(unsigned char adress,unsigned char *key,unsigned char *oNum)
{
	unsigned char s;//读出2个字节数据TagType--卡片类型代码
	char status=MI_ERR;
	unsigned char card_num[4];   		//IC卡的卡号
	unsigned char i;
		
	status=PcdRequest(0x52,&s);    //搜索卡片类型
	status=PcdAnticoll(card_num);  //读卡号
	status=PcdSelect(card_num);    //选卡
	if(status ==MI_OK)
	{
	//验证卡片密码
	// PICC_AUTHENT1A  验证A密钥
	// PICC_AUTHENT1B  验证B密钥
	status=PcdAuthState(PICC_AUTHENT1A,adress,key,card_num);
	status=PcdWrite(adress,oNum);
		if(status == MI_OK)
		{
			printf("write data sucess!!\n");
		}
	}
		PcdHalt();
		sleep(1.5);
	return status;
}


// 返回值为  ：1 M1卡
// 返回值为  ：0 无效卡片类型

int uid_hanshu()
{
	char status;
	unsigned char ulen;
	unsigned char zhilin1[1]={0x40};
	unsigned char zhilin2[1]={0x43};
	unsigned char test_num[2]={0xa0,0x00};
	unsigned char rfid_num[16]={0xf2,0x7b,0x24,0x3c, 
								0x91,0x08,0x04,0x00, 
								0x01,0x6f,0x01,0x6d,
								0x45,0x68,0xf8,0x1d };
	unsigned char card_num[4];
	unsigned char buff[3];
	unsigned char s;//读出2个字节数据TagType--卡片类型代码
	unsigned char card_type[2];
	unsigned char typeIC[2];
	unsigned char card_num22[2]={0x00,0x00};  //M1卡
	unsigned char card_num23[2]={0x0a,0x0a}; //UID卡
	
	status=PcdRequest(0x52,&s);    //搜索卡片类型
	status=PcdAnticoll(card_num);  //读卡号
	status=PcdSelect(card_num);    //选卡
	status=PcdHalt();//休眠
	setBitMask(BitFramingReg, 0x87);
	status=PcdComMF522(PCD_TRANSCEIVE,zhilin1,1,buff,&ulen);
	printf("tesu zhilin1\n%x\n",buff[0]);
	card_type[0]=buff[0];
	setBitMask(BitFramingReg, 0x80);
	status=PcdComMF522(PCD_TRANSCEIVE,zhilin2,1,buff,&ulen);
	printf("tesu zhilin2\n%x\n",buff[0]);
	card_type[1]=buff[0];

	CalulateCRC(test_num,2,&test_num[2]);
	status=PcdComMF522(PCD_TRANSCEIVE,test_num,4,buff,&ulen);
	printf("tesu zhilin3\n%x\n",buff[0]);
	typeIC[1]=buff[0];
	
	CalulateCRC(rfid_num,16,&rfid_num[16]);
	status=PcdComMF522(PCD_TRANSCEIVE,rfid_num,18,buff,&ulen);
	printf("tesu zhilin4\n%x\n",buff[0]);
	typeIC[2]=buff[0];
	
	
	if(memcmp(card_type,card_num22,2)==0)
	{
		printf("\nM1 card\n");
		return 1;
	}
	
	 if(memcmp(card_type,card_num23,2)==0)
	{
		printf("\nUID card\n");
		return 0;
	}
	
return 0;	
} 

int RFID_comparison(const unsigned char *user_id)
{
	int i=0;
	int j=0;
	unsigned char keyA[6]={0xff,0xff,0xff,0xff,0xff,0xff};
	unsigned int btime;
	char status;
	
	memset(&randnum[0],0,16*sizeof(unsigned char)); //清空16字节缓冲区数组
	
	for(j=0;j<3;j++)
	{
		i=uid_hanshu(); // 1 为M1卡和无卡  0UID卡 
		if(i==0)
		{
			return 1;
		}	
		for(i=0;i<3;i++)
		{	
			status=readMess(1,keyA,randnum);
			status=readMess(1,keyA,randnum);
			if(status==MI_OK)
			{
				printf("\n kaishi \n");
				
				printf("%x %x\n",randnum[0],randnum[1]);
				
				if(memcmp(user_id,randnum,2)==0)
				{
					printf("RFID chenggou!!\n");
					return 0;
				}
			}	
		}
		sleep(1);
	}
	return 1;
 
} 

int main()
{
	int i,j;
	unsigned char keyA[6]={0xff,0xff,0xff,0xff,0xff,0xff};
	unsigned char getnum[16];
	unsigned char id[2]={0x20,0x18};
	unsigned char test_num[16]={0x20,0x18,0x05,0x1e,
								0x1e,0x08,0x04,0x00,
								0x62,0x63,0x64,0x65,
								0x66,0x67,0x68,0x69 };
	
	char status;
	int count=0;
	
	if(!bcm2835_init()) 
		return -1;
	MFRC522_Initializtion();
	
	bcm2835_gpio_fsel(35, BCM2835_GPIO_FSEL_OUTP);
	bcm2835_gpio_write(35, HIGH);
	
 //   printf("please enter the corresponding operation!!\n");
	
///	status=writeMess(1,keyA,test_num);//test能否写入数据
//	printf(" %d \n",status);
//	if(status==254)printf("操作失误\n");
	
	while(1)
	{	
		scanf("%d",&j);
		if(j>=0)
		{
		status=readMess(j,keyA,getnum);
		//status=writeMess(j,keyA,test_num);
		printf(" %d \n",status);
		j= -1;
		}
		
		//uid_hanshu();
		
	//	RFID_comparison(id);
		sleep(1);
	} 
	bcm2835_aux_spi_end();
	bcm2835_close();
	return 0;
}
