#pragma once
enum ECommandType : uint16_t
{
	cmUnknown, cmVMEntry, cmPush, cmPop, cmMov, cmAdd, cmXor, cmTest, cmLea,
	cmUd0, cmRet, cmNor, cmNand, cmCrc, cmCall, cmJmp, cmFstsw, cmFsqrt, cmFchs, cmFstcw, cmFldcw,
	cmFild, cmFist, cmFistp, cmFld, cmFstp, cmFst,
	cmFadd, cmFsub, cmFsubr, cmFisub, cmFisubr, cmFdiv, cmFcomp, cmFmul,
	cmRepe, cmRepne, cmRep, cmDB, cmDW, cmDD, cmDQ,
	cmMovs, cmCmps, cmScas,
	cmMovzx, cmMovsx,

	cmInc, cmDec,
	cmLes, cmLds, cmLfs, cmLgs, cmLss,
	cmXadd, cmBswap,
	cmJmpWithFlag,
	cmAnd, cmSub, cmStos, cmLods, cmNop, cmXchg,
	cmPushf, cmPopf, cmSahf, cmLahf, cmShl, cmShr, cmSal, cmSar, cmRcl, cmRcr, cmRol, cmRor, cmShld, cmShrd,
	cmLoope, cmLoopne, cmLoop, cmJCXZ,
	cmIn, cmIns, cmOut, cmOuts, cmWait,
	cmCbw, cmCwde, cmCdqe, cmCwd, cmCdq, cmCqo,
	cmClc, cmStc, cmCli, cmSti, cmCld, cmStd,
	cmNot, cmNeg, cmDiv, cmImul, cmIdiv, cmMul,
	cmOr, cmAdc, cmCmp, cmSbb,
	cmPusha, cmPopa,

	cmClflush, cmPause,

	cmBound, cmArpl, cmDaa, cmDas, cmAaa, cmAam, cmAad, cmAas, cmEnter, cmLeave, cmInt, cmInto, cmIret,
	cmSetXX, cmCmov,

	cmAddpd, cmAddps, cmAddsd, cmAddss,
	cmAndpd, cmAndps, cmAndnpd, cmAndnps,
	cmCmppd, cmCmpps, cmCmpsd, cmCmpss,
	cmComisd, cmComiss,
	cmCvtdq2ps, cmCvtpd2dq, cmCvtdq2pd, cmCvtpd2pi, cmCvtps2pi,
	cmCvtpd2ps, cmCvtps2pd, cmCvtpi2pd, cmCvtpi2ps, cmCvtps2dq,
	cmCvtsd2si, cmCvtss2si, cmCvtsd2ss, cmCvtss2sd,
	cmCvttpd2pi, cmCvttps2pi, cmCvttpd2dq, cmCvttps2dq,
	cmCvttsd2si, cmCvttss2si,
	cmDivpd, cmDivps, cmDivsd, cmDivss,
	cmMaxpd, cmMaxps, cmMaxsd, cmMaxss,
	cmMinpd, cmMinps, cmMinsd, cmMinss,
	cmMulpd, cmMulps, cmMulsd, cmMulss,
	cmOrpd, cmOrps,

	cmMovd, cmMovq, cmMovntq, cmMovapd, cmMovaps, cmMovdqa, cmMovdqu,
	cmMovdq2q, cmMovq2dq,
	cmMovhlps, cmMovhpd, cmMovhps, cmMovlhps, cmMovlpd, cmMovlps,
	cmMovmskpd, cmMovmskps,
	cmMovnti,
	cmMovntpd, cmMovntps,
	cmMovsd, cmMovss,
	cmMovupd, cmMovups,

	cmPmovmskb, cmPsadbw,
	cmPshufw, cmPshufd, cmPshuflw, cmPshufhw,
	cmPsubb, cmPsubw, cmPsubd, cmPsubq,
	cmPsubsb, cmPsubsw,
	cmPsubusb, cmPsubusw,
	cmPaddb, cmPaddw, cmPaddd, cmPaddq,
	cmPaddsb, cmPaddsw,
	cmPaddusb, cmPaddusw,
	cmPavgb, cmPavgw,
	cmPinsrb, cmPinsrw, cmPinsrd, cmPinsrq, cmPextrw,
	cmPmaxsb, cmPmaxsw, cmPmaxsd, cmPmaxub, cmPmaxuw, cmPmaxud,
	cmPminsb, cmPminsw, cmPminsd, cmPminub, cmPminuw, cmPminud,
	cmPmulhuw, cmPmulhw, cmPmullw, cmPmuludq, cmPmulld,
	cmPsllw, cmPslld, cmPsllq, cmPslldq,
	cmPsraw, cmPsrad,
	cmPsrlw, cmPsrld, cmPsrlq, cmPsrldq,

	cmPunpcklbw, cmPunpcklwd, cmPunpckldq, cmPunpcklqdq, cmPunpckhqdq,

	cmPackusdw, cmPcmpgtb, cmPcmpgtw, cmPcmpgtd, cmPcmpeqb, cmPcmpeqw, cmPcmpeqd, cmEmms,
	cmPacksswb, cmPackuswb, cmPunpckhbw, cmPunpckhwd, cmPunpckhdq, cmPackssdw, cmPand, cmPandn, cmPor, cmPxor, cmPmaddwd,
	cmRcpps, cmRcpss,
	cmRsqrtss, cmMovsxd,
	cmShufps, cmShufpd,
	cmSqrtpd, cmSqrtps, cmSqrtsd, cmSqrtss,
	cmSubpd, cmSubps, cmSubsd, cmSubss,
	cmUcomisd, cmUcomiss,
	cmUnpckhpd, cmUnpckhps,
	cmUnpcklpd, cmUnpcklps,
	cmXorpd, cmXorps,

	cmBt, cmBts, cmBtr, cmBtc, cmXlat, cmCpuid, cmRsm, cmBsf, cmBsr, cmCmpxchg, cmCmpxchg8b,
	cmHlt, cmCmc,
	cmLgdt, cmSgdt, cmLidt, cmSidt, cmSmsw, cmLmsw, cmInvlpg,
	cmLar, cmLsl, cmClts, cmInvd, cmWbinvd, cmUd2, cmWrmsr, cmRdtsc, cmRdmsr, cmRdpmc,

	cmFcom, cmFdivr,
	cmFiadd, cmFimul, cmFicom, cmFicomp, cmFidiv, cmFidivr,
	cmFaddp, cmFmulp, cmFsubp, cmFsubrp, cmFdivp, cmFdivrp,
	cmFbld, cmFbstp,

	cmFfree, cmFrstor, cmFsave, cmFucom, cmFucomp,

	cmFldenv, cmFstenvm,
	cmFxch, cmFabs, cmFxam,
	cmFld1, cmFldl2t, cmFldl2e, cmFldpi, cmFldlg2, cmFldln2,

	cmFldz, cmFyl2x, cmFptan, cmFpatan, cmFxtract, cmFprem1, cmFdecstp, cmFincstp,
	cmFprem, cmFyl2xp1, cmFsincos, cmFrndint, cmFscale, cmFsin, cmFcos, cmFtst,
	cmFstenv, cmF2xm1, cmFnop, cmFinit, cmFclex, cmFcompp,

	cmSysenter, cmSysexit, cmSldt, cmStr, cmLldt, cmLtr, cmVerr, cmVerw,
	cmSfence, cmLfence, cmMfence, cmPrefetchnta, cmPrefetcht0, cmPrefetcht1, cmPrefetcht2, cmPrefetch, cmPrefetchw,
	cmFxrstor, cmFxsave, cmLdmxcsr, cmStmxcsr,

	cmFcmovb, cmFcmove, cmFcmovbe, cmFcmovu, cmFcmovnb, cmFcmovne, cmFcmovnbe, cmFcmovnu,

	cmFucomi, cmFcomi,
	cmFucomip, cmFcomip, cmFucompp,

	cmVmcall, cmVmlaunch, cmVmresume, cmVmxoff, cmMonitor, cmMwait, cmXgetbv, cmXsetbv, cmVmrun, cmVmmcall,
	cmVmload, cmVmsave, cmStgi, cmClgi, cmSkinit, cmInvlpga, cmSwapgs, cmRdtscp, cmSyscall, cmSysret, cmFemms, cmGetsec,
	cmPshufb, cmPhaddw, cmPhaddd, cmPhaddsw, cmPmaddubsw, cmPhsubw, cmPhsubd, cmPhsubsw, cmPsignb, cmPsignw, cmPsignd, cmPmulhrsw,
	cmPabsb, cmPabsw, cmPabsd, cmMovbe, cmPalignr, cmRsqrtps, cmVmread, cmVmwrite, cmSvldt, cmRsldt, cmSvts, cmRsts,
	cmXsave, cmXrstor, cmVmptrld, cmVmptrst, cmMaskmovq, cmFnstenv, cmFnstcw, cmFstp1, cmFneni, cmFndisi, cmFnclex, cmFninit,
	cmFsetpm, cmFisttp, cmFnsave, cmFnstsw, cmFxch4, cmFcomp5, cmFfreep, cmFxch7, cmFstp8, cmFstp9, cmHaddpd, cmHsubpd,
	cmAddsubpd, cmAddsubps, cmMovntdq, cmFcom2, cmFcomp3, cmHaddps, cmHsubps, cmMovddup, cmMovsldup, cmCvtsi2sd, cmCvtsi2ss,
	cmMovntsd, cmMovntss, cmLddqu, cmMovshdup, cmPopcnt, cmTzcnt, cmLzcnt,
	cmPblendvb, cmPblendps, cmPblendpd, cmPblendw, cmPtest, cmPmovsxbw, cmPmovsxbd, cmPmovsxbq, cmPmovsxwd, cmPmovsxwq, cmPmovsxdq, cmPmuldq,
	cmPcmpeqq, cmMovntdqa, cmXsaveopt, cmMaskmovdqu, cmUd1, cmPcmpgtq,
	cmAesdec, cmAesdeclast, cmAesenc, cmAesenclast, cmAesimc, cmAeskeygenassist,
	cmRdrand, cmRdseed,
	cmPmovzxbw, cmPmovzxbd, cmPmovzxbq, cmPmovzxwd, cmPmovzxwq, cmPmovzxdq,

	cmFnmadd132sd, cmFnmadd213sd, cmFnmadd231sd,
	cmFnmadd132ss, cmFnmadd213ss, cmFnmadd231ss,

	cmUleb, cmSleb, cmDC,
	cmVbroadcastss, cmVbroadcastsd, cmVbroadcastf128, cmVperm2f128, cmVpermilpd, cmVpermilps, cmRoundpd, cmRoundps, cmCrc32, cmPextrb, cmPextrd, cmPextrq, cmVzeroupper,
	cmVzeroall, cmBlendpd, cmBlendps, cmBlendvpd, cmBlendvps, cmDpps, cmExtractf128, cmInsertf128, cmMaskmovpd, cmMaskmovps,
	cmVtestps, cmVtestpd, cmPcmpistri
};
enum EDirection : uint16_t
{
	dNone, dBefore, dAfter
};

struct REGS
{
	struct
	{
		uint64_t r_rax;
		uint64_t r_rcx;
		uint64_t r_rdx;
		uint64_t r_rbx;
		uint64_t r_rsp;
		uint64_t r_rbp;
		uint64_t r_rsi;
		uint64_t r_rdi;
		uint64_t r_r8;
		uint64_t r_r9;
		uint64_t r_r10;
		uint64_t r_r11;
		uint64_t r_r12;
		uint64_t r_r13;
		uint64_t r_r14;
		uint64_t r_r15;
		uint64_t r_rip;
		uint64_t r_rfl;
		uint64_t r_gs;
		uint64_t r_es;
		uint64_t r_ds;
		uint64_t r_fs;
		uint64_t r_ss;
		uint64_t r_cs;
	} regs;
};

struct SEG_MAP
{
	char            name[MAXCHAR];
	uint64_t		base;
	unsigned int	size;
};