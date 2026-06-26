// Copyright (C) 2026 David Duchet
// SPDX-License-Identifier: Apache-2.0

#ifndef _GALDATASTRUCTURES_INCLUDED
#define _GALDATASTRUCTURES_INCLUDED

#pragma pack (1)

//Message Ids to be put in the field messageid of each returned structure (MANDATORY)
#ifndef UNKNOWN_MESSAGE_TYPE
#define UNKNOWN_MESSAGE_TYPE	0
#define POSTPONED_MESSAGE_TYPE	65536
#endif 

enum gal_msg_id
{
GAL_ALM_TYPE = 3000,
GAL_ALMCOLLECT_TYPE,
GAL_RANGE_TYPE,
GAL_POS_TYPE,
GAL_EPHEM_TYPE,
GAL_RAWEPHEM_TYPE,
GAL_IONO_TYPE,
GAL_TIME_TYPE,
GAL_IONOTIME_TYPE,
GAL_SUBFRAME_TYPE,
GAL_SATORBIT_TYPE
};

enum gal_medll_msg_id
{
GAL_MULTIPATHMET_TYPE = 4001,
GAL_SATDATA_TYPE,
GAL_TRACKSTATUS_TYPE
};

/*
#define GAL_ALM_TYPE			3000
#define GAL_ALMCOLLECT_TYPE 	3001
#define GAL_RANGE_TYPE			3002
#define GAL_POS_TYPE			3003
#define GAL_EPHEM_TYPE			3004
#define GAL_RAWEPHEM_TYPE		3005
#define GAL_IONO_TYPE			3006
#define GAL_TIME_TYPE			3007
#define GAL_IONOTIME_TYPE		3008
#define GAL_SUBFRAME_TYPE		3009
#define GAL_SATORBIT_TYPE		3010

#define GAL_MULTIPATHMET_TYPE	4001
#define GAL_SATDATA_TYPE 		4002
#define GAL_TRACKSTATUS_TYPE	4003
*/

#ifndef _PEG_MSG_BASE_STRUCTURE_DEFINED
#define _PEG_MSG_BASE_STRUCTURE_DEFINED

#define DOUBLE_DONOTUSE	(-1e307)
#define INT_DONOTUSE	((long)0x80000000)
#define STRING_DONOTUSE ("")

#define CRC_NOTOK		0
#define CRC_OK			1	
#define CRC_NOTCHECKED	2

// base type definition for each message
struct MessageType
{
	
	long messageid;				// message id MANDATORY in each derived structure
	
	//--- reception time information 

	//
	double			MessageTime;	// reception time seconds 
	long			MessageWeek;	// reception time week
};

#endif // _PEG_MSG_BASE_STRUCTURE_DEFINED


// assumption: delta range must be set to zero when a loss of lock on phase occurs

#define MY_MAX_CHAN 257

#define FREQ_UNKNOWN 0
#define FREQ_L1      1
#define FREQ_E5a     5
#define FREQ_E6      6
#define FREQ_E5b	 7
#define FREQ_E5		 8

#define CODE_UNKNOWN    0
#define CODE_A          1
#define CODE_B          2
#define CODE_C		    3
#define CODE_D			4
#define CODE_I		    5
#define CODE_L		    6
#define CODE_M		    7
#define CODE_N		    8
#define CODE_Q			9
#define CODE_S			10
#define CODE_W			11
#define CODE_X			12 //B+C or I+Q
#define CODE_Y			13  
#define CODE_Z			14  //A+B+C

const double ChannelBand[9] = {0,1.57542E+09,1.2276E+09,0,0,1.17645E+09,1.27875E+09,1.20714E+09,1.191795E+09};


// type definition of decoded GNSS range messages native to each receiver
struct GALRangeDecodedType : public MessageType
{
	struct RangeType 
	{
		long	svid;			// satellite PRN number (GAL,GLONASS,SBAS)
		double	prange; 		// pseudorange  code (m)
		double	adr;			// accumulated carrier phase (cycles)
		double	doppler;		// Doppler Frequency  (Hz)
		double	snr;			// Signal to Noise relation (dB-Hz)
		double	locktime;		// time of continuous tracking (seconds)
		long	chanStatus;		// channel tracking status
		double   gutc;			// for transmit time receivers, the reception time
		
		long	chanNum;		// channel number
		long	frequency;		// frequency type of measurement (L1, L2, L5)
		long	code;			// code type (CA, P, P codeless)
		bool	phasevalid;		// phase measurement valid flag (true - valid, false - not valid)
		bool	codevalid;		// code measurement valid flag (true - valid, false - not valid)	
		
		bool	chanvalid;		// channel data validity flag (do not use flag) (true - data from channel is valid, false - not valid)
		
	};
	
	long		obs;			// number of observations 
	long		recstat;		// receiver status

	long		recnormaloperation;		// receiver normal operation flag (0: no receiver error login this range log, >0: error)
	bool		posvalid;		// position solution valid (true: position solution valid)
	
	RangeType chans[MY_MAX_CHAN]; // range information for each channel

	RangeType prn_freq_chans[MY_MAX_CHAN][11]; // matrix containing one range type per PRN and Frequency
};



// type definition of decoded GNSS position messages native to each receiver
struct GALPositionDecodedType : public MessageType
{
	double	 latitude;		// latitude in degrees
	double	 longitude; 	// longitude in degrees
	double	 height;		// altitude in meters wgs84
	long	 solustatus;	// solution status (0 = solution computed, error otherwise)
	long	 satc;			// number of satellites used in computation (-1 if value unavailable)
};



// type definition of decoded GAL ephemeris data	   
struct GALEphDecodedType  : public MessageType 
{
	//--- ephemeris data information 
	unsigned long	SVN;			// SV Prn
	unsigned long	Source;			// Source
	long			Toc;			// Reference Time Clock
	double			af2;			// Satellite Clock Correction Param.
	double			af1;			// Satellite Clock Correction Param.
	double			af0;			// Satellite Clock Correction Param.
	double			af0_1;			// Satellite Clock Correction Param.
	unsigned long   WNToc;
	unsigned long   WNToe;
	unsigned long   IODNav;
	double			Crs;			// Amplitude of Sine HCT to Orbit Radius
	double			DeltaN;			// Mean Motion Difference from Computed Value
	double			M0;				// Mean Anomaly at Reference Time
	double			Cuc;			// Amplitude of Cosine HCT to Arg. of Latitude
	double			Ecc;			// Eccentricity
	double			Cus;			// Amplitude of Sine HCT to Arg. of Latitude
	double			sqrtA;			// Square root of semi-major axis
	long			Toe;			// Reference time ephemeris;
	double			Cic;			// Amplitude of Cosine HCT to Angle of Inclin.
	double			Omega0;			// Longitude of Ascending Node at weekly epoch
	double			Cis;			// Amplitude of Sine HCT to Angle of Inclin.
	double			i0;				// Inclination Angle at Reference Time
	double			Crc;			// Amplitude of Cosine HCT to Orbit Radius
	double			Omega;			// Argument of Perigee
	double			OmegaDot;		// Rate of Right Ascension
	double			IDot;			// Rate of Inclination Angle
	
	bool			HealthAndSisaInBinary; // see below to know what to put inside
	
	// HealthAndSisaInBinary=false => septentrio decoding
	unsigned long	Health_OSSOL;
	unsigned long	Health_PRS;
	unsigned long	SISA_L1E5a;
	unsigned long	SISA_L1E5b;
	unsigned long	SISA_L1AE6A;
	
	// HealthAndSisaInBinary=true => binary decoding
	unsigned long DataSources;
	unsigned long SISA;
	unsigned long SVHealth;
	
	double BGD_L1E5a; //Rinex column TGD
	double BGD_L1E5b; //Rinex column SPARE1
	
	//ignored in Rinex
	double BGD_L1AE6A;
	unsigned long CNAVEncrypt;
	unsigned long SISA_used;
	
	long			CRC;			// ephemeris crc
};


// assumptions made for the use of the binary GAL ephemeris data structure:

// the GAL binary data from the subframes 1 - 3 is contained in the structure
// items 'SubFrame1', 'SubFrame2' and 'SubFrame3', 

// in each subframe the 10 GAL words are contained and the parity information
// is removed, thus giving 10 time 24 bits (i.e. 240 bits) information arran-
// ged in an array of the size 30 * 8 bits (i.e. 240 bits). 

// first eight MSB of subframe are represented by SubFrameX[0], last eight LSB
// of subframe are represented by SubFrameX[29]

// type definition of decoded GAL ephemeris data 
struct GALEphBinaryType : public MessageType
{
	//--- SVN and binary information 

	//
	unsigned char	SVN;				// SV Prn
	unsigned char	SubFrame1[30];		// message content of subframe 1 without parity
	unsigned char	SubFrame2[30];		// message content of subframe 2 without parity
	unsigned char	SubFrame3[30];		// message content of subframe 3 without parity
} ; 

//====================================================================================//
//====================================================================================//

// type definition of Satellite position, velocity and acceleration and clock parameters
struct GALSatOrbitDataType : public MessageType		   
{
	//
	unsigned char SVN;		// SV PRN
	
	int wn0;				// reference Week number (put -1 if not available)
	double	t0;				// time of applicability (put -1 if not available)

	double	X;				// position x
	double	Y;				// position y
	double	Z;				// position z
	double	Xvel;			// velocity x (put DOUBLE_DONOTUSE value if not available)
	double	Yvel;			// velocity y (put DOUBLE_DONOTUSE value if not available)
	double	Zvel;			// velocity z (put DOUBLE_DONOTUSE value if not available)
	double	Xacc;			// acceleration x (put DOUBLE_DONOTUSE value if not available)
	double	Yacc;			// acceleration y (put DOUBLE_DONOTUSE value if not available)
	double	Zacc;			// acceleration z (put DOUBLE_DONOTUSE value if not available)

	double	clk_offset;		// clock offset (put DOUBLE_DONOTUSE value if not available)
	double	clk_drift;		// clock drift (put DOUBLE_DONOTUSE value if not available)
};

// assumptions made for the use of the decoded GAL almanac data structure:

// the developer must be able to fill in every item of the data structure,
// in particular the items 'MessageTime' and 'MessageWeek' according to 
// the specifications of the PEGASUS format


// type definition of decoded GAL almanac data		 
struct GALAlmDecodedType : public MessageType  
{
	int 	SVID;						// Satellite PRN number 
	int 	Source;					    // G/NAV, I/NAV, or F/NAV
	double	Ecc;						// Eccentricity 			 
	double	RefTime;					// Almanac reference time	
	double	Inclin; 					// Angle of inclination
	double	OmegaDot;					// Rate of right ascension
	double	DSqrtA;						// Semi-major axis
	double  Omega_0;
	double	w;							// Argument of perigee
	double	M0; 						// Mean anomaly
	double	af1;						// Clock aging parameter
	double	af0;						// Clock aging parameter
	int 	RefWeek;					// Almanac reference week
	unsigned char SVIDA;
	int		Health;			 	 
	double	MM_Corr;					// Corrected mean motion	 
	unsigned char IODa;
	double	RAsc;						// Right ascension
	//int 	Health_Alm; 				// SV health from almanac
};

// type definition of collection of decoded GAL almanac data
// contains multiple alamanac messages - one for each GAL satellite
struct GALAlmCollectType : public MessageType  
{
	struct AlmType
	{
		int 	SVID;						// Satellite PRN number 
		int 	Source;					    // G/NAV, I/NAV, or F/NAV
		double	Ecc;						// Eccentricity 			 
		double	RefTime;					// Almanac reference time	
		double	Inclin; 					// Angle of inclination
		double	OmegaDot;					// Rate of right ascension
		double	DSqrtA;						// Semi-major axis
		double  Omega_0;
		double	w;							// Argument of perigee
		double	M0; 						// Mean anomaly
		double	af1;						// Clock aging parameter
		double	af0;						// Clock aging parameter
		int 	RefWeek;					// Almanac reference week
		unsigned char SVIDA;
		int		Health;			 	 
		double	MM_Corr;					// Corrected mean motion	 
		unsigned char IODa;	
		double	RAsc;						// Right ascension
	};
	
	long count;							// almanac messages count
	AlmType message[32];				// almanac messages
};


// assumptions made for the use of the decoded GAL ionospheric data structure:

// the developer must be able to fill in every item of the data structure,
// in particular the items 'MessageTime' and 'MessageWeek' according to 
// the specifications of the PEGASUS format

// type definition of decoded GAL ionospheric data		 
struct GALIonoDecodedType : public MessageType	
{
	//--- decoded ionospheric information

	//
	unsigned char SVID;
	unsigned char Source;
	double ai0 ; 					// alpha polynominial constant term  
	double ai1 ; 					// alpha polynominial first order term	
	double ai2 ; 					// alpha polynominial second order term  
	unsigned char StormFlags;
/*	double alpha3 ; 					// alpha polynominial third order term	
	double beta0 ;						// beta polynominial constant term	
	double beta1 ;						// beta polynominial first order term  
	double beta2 ;						// beta polynominial second order term	
	double beta3 ;						// beta polynominial third order term  
*/
};


// assumptions made for the use of the decoded GAL UTC time transformation data structure:

// the developer must be able to fill in every item of the data structure,
// in particular the items 'MessageTime' and 'MessageWeek' according to 
// the specifications of the PEGASUS format


// type definition of decoded GAL UTC data		 
struct GALTimeDecodedType : public MessageType	
{
	//--- decoded UTC time transformation information

	//
	unsigned char SVID  ;
	unsigned char Source;
	double a0			;				// polynominial constant term  
	double a1			; 				// polynominial first order term   
	int    T0_UTC		; 				// UTC reference time - seconds  
	int    WN0_UTC		;				// UTC reference time - week  
	int    WN_LSF		; 				// week number for leap seconds effects  
	int    DeltaT_LSF	; 				// delta time due to leap seconds (future)
	int    DeltaT_LS	;				// delta time due to leap seconds (past)
	int    DN_LSF		; 				// day number for leap seconds effects	
};

struct GALIonoTimeType : public MessageType 
{
	GALTimeDecodedType time;	// time message
	GALIonoDecodedType iono;	// iono message
};


// assumptions made for the use of the binary subframe page data structure:

// the GAL binary data from the pages of subframes 4 or 5 is contained in the
// structure item 'SubFrame' 

// in the subframe the 10 GAL words are contained and the parity information
// is removed, thus giving 10 time 24 bits (i.e. 240 bits) information arran-
// ged in an array of the size 30 * 8 bits (i.e. 240 bits). 

// first eight MSB of subframe are represented by SubFrame[0], last eight LSB
// of subframe are represented by SubFrame[29]

// type definition of binary GAL subframe page data 	  
struct GALSubframePageBinaryType : public MessageType  
{
	//--- binary information 

	//
	unsigned char	SubFrame[30];		// message content of subframe page without parity
	long			SubFrameNumber;		// number of the subframe (1 to 5)
};

//#define MAX_CHAN 24
#define MAX_GALSAT 210

// assumptions made for the use of the Satellite specific data structure:
// type definition of decoded Satellite specific data
struct GALSatDataType : public MessageType
{
	struct SatDataItem
	{
		int		SVID;		// Satellite PRN number
		double	Azimuth;	// azimuth
		double	Elev;		// elevation
		int     RjCode;		// reject code
		unsigned long Health;// health
	};

	int		numobs;				// number of observations
	int		solstatus;			// solution status
	SatDataItem	data[MAX_GALSAT]; // satellite related data
}; 

struct GALMultiPathMeterType : public MessageType
{
	int		svid;
	double	delay;
	double	ampl;
	double	phase;
	double	phaseres[12];
	double	quadphaseres[12];

	int		chanstatus;
	int		receiverstatus;

};


#pragma pack ()

#endif //#define _GALDATASTRUCTURES_INCLUDED
